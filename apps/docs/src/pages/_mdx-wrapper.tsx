"use client";

import type React from "react";
import { Layout } from "vocs";

export default function MdxWrapper({ children }: { children: React.ReactNode }) {
  return <Layout>{children}</Layout>;
}
