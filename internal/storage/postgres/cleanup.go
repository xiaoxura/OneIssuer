package postgres

// cleanupBatchSize keeps every cleanup transaction small enough to commit
// useful progress under a bounded operation deadline.
const cleanupBatchSize int32 = 250
