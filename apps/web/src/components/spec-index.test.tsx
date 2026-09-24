import { describe, expect, it } from 'vitest'
import { categories } from '../lib/spec-data'
import { SPEC_ICONS } from './spec-index'

describe('SPEC_ICONS', () => {
  it('has an icon for every listed spec', () => {
    const names = categories.flatMap((cat) => cat.items.map((item) => item.name))
    expect(names.filter((name) => !SPEC_ICONS[name])).toEqual([])
  })

  it('has no icons for specs that are not listed', () => {
    const names = new Set(categories.flatMap((cat) => cat.items.map((item) => item.name)))
    expect(Object.keys(SPEC_ICONS).filter((name) => !names.has(name))).toEqual([])
  })
})
