package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestAuditContractEnumsMatchEveryContractSource keeps the four independent
// audit enum declarations in lockstep. The migration reader follows the
// goose Up history so an older CREATE TABLE check cannot mask a later ALTER.
func TestAuditContractEnumsMatchEveryContractSource(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)

	expected := map[string]map[string]struct{}{
		"event":         mapKeys(validEvents),
		"result":        mapKeys(validResults),
		"target":        mapKeys(validTargets),
		"changed_field": mapKeys(validChangedFields),
	}

	openAPI, err := readOpenAPIAuditEnums(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read OpenAPI audit enums: %v", err)
	}
	migration, err := readFinalAuditChecks(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read final audit checks: %v", err)
	}

	for _, name := range []string{"event", "result", "target", "changed_field"} {
		assertEnumSetEqual(t, "valid "+name+" whitelist vs OpenAPI", expected[name], openAPI[name])
		assertEnumSetEqual(t, "valid "+name+" whitelist vs migration", expected[name], migration[name])
		assertEnumSetEqual(t, "OpenAPI "+name+" vs migration", openAPI[name], migration[name])
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func mapKeys(values map[string]bool) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for value := range values {
		result[value] = struct{}{}
	}
	return result
}

func assertEnumSetEqual(t *testing.T, label string, want, got map[string]struct{}) {
	t.Helper()
	missing := make([]string, 0)
	for value := range want {
		if _, ok := got[value]; !ok {
			missing = append(missing, value)
		}
	}
	extra := make([]string, 0)
	for value := range got {
		if _, ok := want[value]; !ok {
			extra = append(extra, value)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("%s mismatch: missing=%v extra=%v", label, missing, extra)
	}
}

func readOpenAPIAuditEnums(filename string) (map[string]map[string]struct{}, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("decode trailing YAML document: %w", err)
	}
	if err := validateYAMLNode(&document, "OpenAPI"); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, fmt.Errorf("OpenAPI document must contain one root node")
	}

	root := document.Content[0]
	components, err := yamlMappingValue(root, "components")
	if err != nil {
		return nil, err
	}
	schemas, err := yamlMappingValue(components, "schemas")
	if err != nil {
		return nil, err
	}

	schemaNames := map[string]string{
		"event":         "AuditEventType",
		"result":        "AuditResult",
		"target":        "AuditTargetType",
		"changed_field": "AuditChangedField",
	}
	result := make(map[string]map[string]struct{}, len(schemaNames))
	for contractName, schemaName := range schemaNames {
		schema, err := yamlMappingValue(schemas, schemaName)
		if err != nil {
			return nil, err
		}
		typeNode, err := yamlMappingValue(schema, "type")
		if err != nil {
			return nil, fmt.Errorf("OpenAPI schema %s: %w", schemaName, err)
		}
		if typeNode.Kind != yaml.ScalarNode || typeNode.Tag != "!!str" || typeNode.Value != "string" {
			return nil, fmt.Errorf("OpenAPI schema %s type must be the string scalar %q", schemaName, "string")
		}
		enumNode, err := yamlMappingValue(schema, "enum")
		if err != nil {
			return nil, fmt.Errorf("OpenAPI schema %s: %w", schemaName, err)
		}
		if enumNode.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("OpenAPI schema %s enum must be a sequence", schemaName)
		}
		values := make(map[string]struct{}, len(enumNode.Content))
		for index, valueNode := range enumNode.Content {
			if valueNode.Kind != yaml.ScalarNode || valueNode.Tag != "!!str" || valueNode.Value == "" {
				return nil, fmt.Errorf("OpenAPI schema %s enum item %d must be a non-empty string", schemaName, index)
			}
			if _, duplicate := values[valueNode.Value]; duplicate {
				return nil, fmt.Errorf("OpenAPI schema %s enum repeats %q", schemaName, valueNode.Value)
			}
			values[valueNode.Value] = struct{}{}
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("OpenAPI schema %s enum must not be empty", schemaName)
		}
		result[contractName] = values
	}
	return result, nil
}

func validateYAMLNode(node *yaml.Node, path string) error {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return fmt.Errorf("%s must contain exactly one document value", path)
		}
		return validateYAMLNode(node.Content[0], path)
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s mapping has an unmatched key", path)
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s has a non-string mapping key", path)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%s repeats mapping key %q", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateYAMLNode(node.Content[index+1], path+"."+key.Value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for index, child := range node.Content {
			if err := validateYAMLNode(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return nil
	case yaml.AliasNode:
		return fmt.Errorf("%s uses an unsupported YAML alias", path)
	default:
		return fmt.Errorf("%s has an unsupported YAML node kind %d", path, node.Kind)
	}
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) (*yaml.Node, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("YAML path %q is not a mapping", key)
	}
	for index := 0; index < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1], nil
		}
	}
	return nil, fmt.Errorf("YAML path component %q is missing", key)
}

type auditCheckDefinition struct {
	expression string
	filename   string
}

var (
	auditEnumConstraints = map[string]string{
		"audit_events_type_valid":               "event",
		"audit_events_result_valid":             "result",
		"audit_events_target_valid":             "target",
		"audit_events_changed_fields_whitelist": "changed_field",
	}
	auditConstraintPattern = regexp.MustCompile(`(?is)\bCONSTRAINT\s+([A-Za-z_][A-Za-z0-9_]*)\s+CHECK\s*\(`)
	auditConstraintNames   = map[string]struct{}{
		"audit_events_type_valid":               {},
		"audit_events_result_valid":             {},
		"audit_events_target_valid":             {},
		"audit_events_changed_fields_whitelist": {},
		"audit_events_request_id_safe":          {},
	}
)

func readFinalAuditChecks(migrationsDir string) (map[string]map[string]struct{}, error) {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no SQL migrations found in %s", migrationsDir)
	}
	sort.Strings(files)
	active := make(map[string]auditCheckDefinition, len(auditEnumConstraints))
	for _, filename := range files {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		up, err := gooseUpSection(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(filename), err)
		}
		statements, err := splitSQLStatements(up)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(filename), err)
		}
		for index, statement := range statements {
			if err := applyAuditStatement(statement, filepath.Base(filename), active); err != nil {
				return nil, fmt.Errorf("%s statement %d: %w", filepath.Base(filename), index+1, err)
			}
		}
	}
	if len(active) != len(auditEnumConstraints) {
		missing := make([]string, 0)
		for name := range auditEnumConstraints {
			if _, ok := active[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("final audit CHECK set is incomplete; missing %v", missing)
	}

	result := make(map[string]map[string]struct{}, len(auditEnumConstraints))
	for constraint, contractName := range auditEnumConstraints {
		definition := active[constraint]
		values, err := parseAuditCheck(contractName, definition.expression)
		if err != nil {
			return nil, fmt.Errorf("%s from %s: %w", constraint, definition.filename, err)
		}
		result[contractName] = values
	}
	return result, nil
}

func gooseUpSection(sql string) (string, error) {
	marker := regexp.MustCompile(`(?m)^\s*--\s*\+goose\s+(Up|Down)\s*$`)
	matches := marker.FindAllStringSubmatchIndex(sql, -1)
	if len(matches) != 2 || !strings.EqualFold(sql[matches[0][2]:matches[0][3]], "Up") || !strings.EqualFold(sql[matches[1][2]:matches[1][3]], "Down") {
		return "", fmt.Errorf("expected exactly one goose Up section followed by Down")
	}
	if matches[0][0] >= matches[1][0] {
		return "", fmt.Errorf("goose Up section must precede Down")
	}
	return sql[matches[0][1]:matches[1][0]], nil
}

func applyAuditStatement(statement, filename string, active map[string]auditCheckDefinition) error {
	normalized := normalizeSQL(statement)
	if normalized == "" {
		return nil
	}
	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "create table audit_events ") {
		return applyCreateAuditTable(normalized, filename, active)
	}
	if strings.HasPrefix(lower, "alter table audit_events ") {
		return applyAlterAuditTable(normalized, filename, active)
	}
	for name := range auditConstraintNames {
		if strings.Contains(lower, strings.ToLower(name)) {
			return fmt.Errorf("audit constraint appears in an unsupported SQL statement")
		}
	}
	return nil
}

func applyCreateAuditTable(statement, filename string, active map[string]auditCheckDefinition) error {
	open := strings.Index(statement, "(")
	if open < 0 {
		return fmt.Errorf("audit table has no column list")
	}
	closeIndex, err := matchingDelimiter(statement, open, '(', ')')
	if err != nil {
		return err
	}
	if strings.TrimSpace(statement[closeIndex+1:]) != "" {
		return fmt.Errorf("audit table statement has unsupported trailing syntax")
	}
	definitions, err := extractCreateChecks(statement[open+1 : closeIndex])
	if err != nil {
		return err
	}
	for name, expression := range definitions {
		if _, enum := auditEnumConstraints[name]; !enum {
			continue
		}
		if _, exists := active[name]; exists {
			return fmt.Errorf("audit CHECK %s is defined more than once without a drop", name)
		}
		active[name] = auditCheckDefinition{expression: expression, filename: filename}
	}
	return nil
}

func extractCreateChecks(body string) (map[string]string, error) {
	definitions := make(map[string]string)
	for cursor := 0; cursor < len(body); {
		location := auditConstraintPattern.FindStringSubmatchIndex(body[cursor:])
		if location == nil {
			break
		}
		name := body[cursor+location[2] : cursor+location[3]]
		open := cursor + location[1] - 1
		closeIndex, err := matchingDelimiter(body, open, '(', ')')
		if err != nil {
			return nil, err
		}
		if _, allowed := auditConstraintNames[name]; !allowed {
			return nil, fmt.Errorf("unknown audit table constraint %q", name)
		}
		if _, duplicate := definitions[name]; duplicate {
			return nil, fmt.Errorf("audit table constraint %s is repeated", name)
		}
		if _, enum := auditEnumConstraints[name]; enum {
			definitions[name] = body[open+1 : closeIndex]
		}
		cursor = closeIndex + 1
	}
	if len(definitions) == 0 {
		return nil, fmt.Errorf("audit table has no supported enum CHECK constraints")
	}
	return definitions, nil
}

func applyAlterAuditTable(statement, filename string, active map[string]auditCheckDefinition) error {
	rest := strings.TrimSpace(statement[len("ALTER TABLE audit_events "):])
	for rest != "" {
		lower := strings.ToLower(rest)
		switch {
		case strings.HasPrefix(lower, "drop constraint "):
			name, consumed, err := parseConstraintName(rest[len("DROP CONSTRAINT "):])
			if err != nil {
				return err
			}
			if _, allowed := auditConstraintNames[name]; !allowed {
				return fmt.Errorf("unknown audit constraint %q", name)
			}
			if _, enum := auditEnumConstraints[name]; enum {
				if _, exists := active[name]; !exists {
					return fmt.Errorf("audit CHECK %s was dropped while inactive", name)
				}
				delete(active, name)
			}
			rest = strings.TrimSpace(rest[len("DROP CONSTRAINT ")+consumed:])
		case strings.HasPrefix(lower, "add constraint "):
			name, consumed, err := parseConstraintName(rest[len("ADD CONSTRAINT "):])
			if err != nil {
				return err
			}
			if _, allowed := auditConstraintNames[name]; !allowed {
				return fmt.Errorf("unknown audit constraint %q", name)
			}
			rest = strings.TrimSpace(rest[len("ADD CONSTRAINT ")+consumed:])
			if !strings.HasPrefix(strings.ToLower(rest), "check ") {
				return fmt.Errorf("audit constraint %s is not a CHECK", name)
			}
			rest = strings.TrimSpace(rest[len("CHECK "):])
			if len(rest) == 0 || rest[0] != '(' {
				return fmt.Errorf("audit constraint %s has no CHECK expression", name)
			}
			closeIndex, err := matchingDelimiter(rest, 0, '(', ')')
			if err != nil {
				return err
			}
			if _, enum := auditEnumConstraints[name]; enum {
				if _, exists := active[name]; exists {
					return fmt.Errorf("audit CHECK %s is added while already active", name)
				}
				active[name] = auditCheckDefinition{expression: rest[1:closeIndex], filename: filename}
			}
			rest = strings.TrimSpace(rest[closeIndex+1:])
		default:
			return fmt.Errorf("unsupported ALTER TABLE audit_events clause %q", rest)
		}
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return fmt.Errorf("audit ALTER clauses must be comma-separated")
		}
		rest = strings.TrimSpace(rest[1:])
	}
	return nil
}

func parseConstraintName(input string) (string, int, error) {
	match := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:\s+|$)`).FindStringSubmatchIndex(input)
	if match == nil {
		return "", 0, fmt.Errorf("audit constraint name is malformed")
	}
	return input[match[2]:match[3]], match[1], nil
}

func parseAuditCheck(contractName, expression string) (map[string]struct{}, error) {
	expression = normalizeSQL(expression)
	switch contractName {
	case "event":
		return parseSimpleSQLList(expression, "event_type IN")
	case "result":
		return parseSimpleSQLList(expression, "result IN")
	case "target":
		return parseTargetSQLList(expression)
	case "changed_field":
		return parseChangedFieldSQLList(expression)
	default:
		return nil, fmt.Errorf("unknown audit contract %q", contractName)
	}
}

func parseSimpleSQLList(expression, prefix string) (map[string]struct{}, error) {
	if !strings.HasPrefix(strings.ToLower(expression), strings.ToLower(prefix)) {
		return nil, fmt.Errorf("CHECK expression must start with %q", prefix)
	}
	rest := strings.TrimSpace(expression[len(prefix):])
	if len(rest) == 0 || rest[0] != '(' {
		return nil, fmt.Errorf("CHECK expression %q has no IN list", prefix)
	}
	closeIndex, err := matchingDelimiter(rest, 0, '(', ')')
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rest[closeIndex+1:]) != "" {
		return nil, fmt.Errorf("CHECK expression %q has unsupported trailing syntax", prefix)
	}
	return parseSQLStringList(rest[1:closeIndex])
}

func parseTargetSQLList(expression string) (map[string]struct{}, error) {
	first, next, err := parseParenthesized(expression, 0)
	if err != nil || !strings.EqualFold(first, "target_type IS NULL AND target_id IS NULL") {
		return nil, fmt.Errorf("target CHECK must begin with the null-target branch")
	}
	rest := strings.TrimSpace(expression[next:])
	if len(rest) < 2 || !strings.EqualFold(rest[:2], "OR") {
		return nil, fmt.Errorf("target CHECK must join branches with OR")
	}
	rest = strings.TrimSpace(rest[2:])
	second, next, err := parseParenthesized(rest, 0)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rest[next:]) != "" {
		return nil, fmt.Errorf("target CHECK has unsupported trailing syntax")
	}
	prefix := "target_type IN"
	if !strings.HasPrefix(strings.ToLower(second), strings.ToLower(prefix)) {
		return nil, fmt.Errorf("target CHECK second branch has no target_type IN list")
	}
	list := strings.TrimSpace(second[len(prefix):])
	if len(list) == 0 || list[0] != '(' {
		return nil, fmt.Errorf("target CHECK target_type IN list is malformed")
	}
	closeIndex, err := matchingDelimiter(list, 0, '(', ')')
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(list[closeIndex+1:]), "AND target_id IS NOT NULL") {
		return nil, fmt.Errorf("target CHECK second branch has unsupported predicates")
	}
	return parseSQLStringList(list[1:closeIndex])
}

func parseChangedFieldSQLList(expression string) (map[string]struct{}, error) {
	prefix := "changed_fields <@ ARRAY"
	if !strings.HasPrefix(strings.ToLower(expression), strings.ToLower(prefix)) {
		return nil, fmt.Errorf("changed-field CHECK must start with %q", prefix)
	}
	rest := strings.TrimSpace(expression[len(prefix):])
	if len(rest) == 0 || rest[0] != '[' {
		return nil, fmt.Errorf("changed-field CHECK has no ARRAY list")
	}
	closeIndex, err := matchingDelimiter(rest, 0, '[', ']')
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(rest[closeIndex+1:]), "::text[]") {
		return nil, fmt.Errorf("changed-field CHECK must cast ARRAY to text[]")
	}
	return parseSQLStringList(rest[1:closeIndex])
}

func parseParenthesized(input string, offset int) (string, int, error) {
	for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t' || input[offset] == '\n') {
		offset++
	}
	if offset >= len(input) || input[offset] != '(' {
		return "", 0, fmt.Errorf("expected parenthesized SQL expression")
	}
	closeIndex, err := matchingDelimiter(input, offset, '(', ')')
	if err != nil {
		return "", 0, err
	}
	return input[offset+1 : closeIndex], closeIndex + 1, nil
}

func parseSQLStringList(input string) (map[string]struct{}, error) {
	values := make(map[string]struct{})
	for offset := 0; ; {
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t' || input[offset] == '\n' || input[offset] == '\r') {
			offset++
		}
		if offset == len(input) {
			break
		}
		if input[offset] != '\'' {
			return nil, fmt.Errorf("enum list contains a non-string value near %q", input[offset:])
		}
		offset++
		var value strings.Builder
		closed := false
		for offset < len(input) {
			if input[offset] != '\'' {
				value.WriteByte(input[offset])
				offset++
				continue
			}
			if offset+1 < len(input) && input[offset+1] == '\'' {
				value.WriteByte('\'')
				offset += 2
				continue
			}
			offset++
			closed = true
			break
		}
		if !closed || value.Len() == 0 {
			return nil, fmt.Errorf("enum list contains an unterminated or empty string")
		}
		if _, duplicate := values[value.String()]; duplicate {
			return nil, fmt.Errorf("enum list repeats %q", value.String())
		}
		values[value.String()] = struct{}{}
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t' || input[offset] == '\n' || input[offset] == '\r') {
			offset++
		}
		if offset == len(input) {
			break
		}
		if input[offset] != ',' {
			return nil, fmt.Errorf("enum list has unexpected token near %q", input[offset:])
		}
		offset++
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("enum list is empty")
	}
	return values, nil
}

func normalizeSQL(statement string) string { return strings.Join(strings.Fields(statement), " ") }

func matchingDelimiter(input string, open int, opening, closing byte) (int, error) {
	if open >= len(input) || input[open] != opening {
		return 0, fmt.Errorf("expected %q delimiter", opening)
	}
	depth := 0
	for index := open; index < len(input); index++ {
		switch input[index] {
		case '\'':
			for index++; index < len(input); index++ {
				if input[index] != '\'' {
					continue
				}
				if index+1 < len(input) && input[index+1] == '\'' {
					index++
					continue
				}
				break
			}
		case '"':
			for index++; index < len(input); index++ {
				if input[index] != '"' {
					continue
				}
				if index+1 < len(input) && input[index+1] == '"' {
					index++
					continue
				}
				break
			}
		default:
			switch input[index] {
			case opening:
				depth++
			case closing:
				depth--
				if depth == 0 {
					return index, nil
				}
				if depth < 0 {
					return 0, fmt.Errorf("unbalanced %q delimiter", closing)
				}
			}
		}
	}
	return 0, fmt.Errorf("unterminated %q delimiter", opening)
}

func splitSQLStatements(input string) ([]string, error) {
	var statements []string
	var statement strings.Builder
	for index := 0; index < len(input); {
		switch {
		case input[index] == '-' && index+1 < len(input) && input[index+1] == '-':
			index += 2
			for index < len(input) && input[index] != '\n' {
				index++
			}
		case input[index] == '/' && index+1 < len(input) && input[index+1] == '*':
			end := strings.Index(input[index+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated SQL block comment")
			}
			index += end + 4
		case input[index] == '\'':
			start := index
			index++
			for index < len(input) {
				if input[index] != '\'' {
					index++
					continue
				}
				if index+1 < len(input) && input[index+1] == '\'' {
					index += 2
					continue
				}
				index++
				break
			}
			if index > len(input) || input[index-1] != '\'' {
				return nil, fmt.Errorf("unterminated SQL string")
			}
			statement.WriteString(input[start:index])
		case input[index] == '"':
			start := index
			index++
			for index < len(input) {
				if input[index] != '"' {
					index++
					continue
				}
				if index+1 < len(input) && input[index+1] == '"' {
					index += 2
					continue
				}
				index++
				break
			}
			if index > len(input) || input[index-1] != '"' {
				return nil, fmt.Errorf("unterminated SQL identifier")
			}
			statement.WriteString(input[start:index])
		case input[index] == '$':
			if delimiter, ok := sqlDollarQuoteAt(input, index); ok {
				end := strings.Index(input[index+len(delimiter):], delimiter)
				if end < 0 {
					return nil, fmt.Errorf("unterminated SQL dollar-quoted body")
				}
				end += index + len(delimiter)
				end += len(delimiter)
				statement.WriteString(input[index:end])
				index = end
			} else {
				statement.WriteByte(input[index])
				index++
			}
		case input[index] == ';':
			if text := strings.TrimSpace(statement.String()); text != "" {
				statements = append(statements, text)
			}
			statement.Reset()
			index++
		default:
			statement.WriteByte(input[index])
			index++
		}
	}
	if text := strings.TrimSpace(statement.String()); text != "" {
		statements = append(statements, text)
	}
	return statements, nil
}

func sqlDollarQuoteAt(input string, offset int) (string, bool) {
	if offset >= len(input) || input[offset] != '$' {
		return "", false
	}
	end := offset + 1
	for end < len(input) && input[end] != '$' {
		if input[end] != '_' &&
			(input[end] < 'a' || input[end] > 'z') &&
			(input[end] < 'A' || input[end] > 'Z') &&
			(input[end] < '0' || input[end] > '9') {
			return "", false
		}
		end++
	}
	if end >= len(input) {
		return "", false
	}
	return input[offset : end+1], true
}
