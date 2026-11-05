const RE = /^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$/

/** Whether release a is later than release b ("v0.5.15" against "v0.5.14"). A version that is not a release is never later. */
export function isNewer(a: string | null | undefined, b: string | null | undefined): boolean {
  const x = RE.exec(a ?? '')
  const y = RE.exec(b ?? '')
  if (!x || !y) return false
  for (let i = 1; i <= 3; i++) {
    const d = Number(x[i]) - Number(y[i])
    if (d !== 0) return d > 0
  }
  return false
}
