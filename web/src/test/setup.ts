import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach } from 'vitest'

beforeEach(() => {
  window.localStorage.clear()
  window.localStorage.setItem('oneissuer.locale', 'en')
})

afterEach(() => {
  cleanup()
  window.localStorage.clear()
})
