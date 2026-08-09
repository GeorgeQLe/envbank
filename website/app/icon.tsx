import { ImageResponse } from "next/og";

export const size = { width: 64, height: 64 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(<div style={{ width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "#101713", color: "#b9f76a", border: "6px solid #b9f76a", borderRadius: 14, fontSize: 35, fontWeight: 800, fontFamily: "monospace" }}>E</div>, size);
}
