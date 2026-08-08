// The clamps only. Formatting a number is not interesting; refusing to format
// one that cannot exist is, because this file is the last thing between a
// broken /proc read (or a hostile subscription) and a sentence the user will
// believe. Every case below was rendered by the shipped bundle against a
// daemon returning it.

import { describe, expect, it } from "vitest";
import { fmtBytes, fmtPct, fmtRate, fmtRelative, fmtTemp } from "./format";

describe("numbers that cannot exist render as no answer", () => {
  it("refuses negative bytes — `mem_available > mem_total`", () => {
    // Rendered "-400000000 B  of 477 MB" on a card whose rail is a fraction of
    // that total. The pair is broken; neither half is a memory reading.
    expect(fmtBytes(-400_000_000)).toBe("—");
    expect(fmtRate(-4_000)).toBe("—");
  });

  it("refuses a percent outside 0-100, and clamps rounding overshoot", () => {
    expect(fmtPct(1_000_000_000)).toBe("—");
    expect(fmtPct(-50)).toBe("—");
    expect(fmtPct(100.4)).toBe("100%"); // multi-core rounding, not a fault
    expect(fmtPct(-0.2)).toBe("0%");
    expect(fmtPct(17.4)).toBe("17%");
  });

  it("refuses a temperature no router has", () => {
    expect(fmtTemp(-273)).toBe("—");
    expect(fmtTemp(45_000)).toBe("—"); // millidegrees read as degrees
    expect(fmtTemp(52)).toBe("52°C");
  });

  it("refuses NaN and Infinity everywhere", () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expect(fmtBytes(bad)).toBe("—");
      expect(fmtPct(bad)).toBe("—");
      expect(fmtTemp(bad)).toBe("—");
    }
  });

  it("still reads an absent rate as no traffic, which it is", () => {
    expect(fmtBytes(undefined)).toBe("0 B");
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtRate(0)).toBe("0 B/s");
  });

  it("never renders a timestamp from the future as a negative age", () => {
    const ahead = new Date(Date.now() + 30_000).toISOString();
    expect(fmtRelative(ahead)).toBe("just now");
  });
});
