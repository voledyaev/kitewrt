import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('request deadlines', () => {
  it('aborts a stalled poll and releases its timer', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn((_url: string, opts: RequestInit) =>
      new Promise((_resolve, reject) => {
        opts.signal!.addEventListener('abort', () => reject(new Error('aborted')))
      })))
    const result = expect(api.getState()).rejects.toThrow('Request timed out')
    await vi.advanceTimersByTimeAsync(15000)
    await result
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps the deadline active while reading the response body', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn(async (_url: string, opts: RequestInit) => ({
      ok: true,
      text: () => new Promise((_resolve, reject) => {
        opts.signal!.addEventListener('abort', () => reject(new Error('aborted body')))
      }),
    })))
    const result = expect(api.getMetrics()).rejects.toThrow('Request timed out')
    await vi.advanceTimersByTimeAsync(15000)
    await result
    expect(vi.getTimerCount()).toBe(0)
  })

  it('clears the timer on success', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, text: async () => '{}' })))
    await api.getState()
    expect(vi.getTimerCount()).toBe(0)
  })
})
