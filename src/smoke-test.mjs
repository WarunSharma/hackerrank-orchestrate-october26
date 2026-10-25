
import { GoogleGenAI } from "@google/genai";
import "node:process";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

try {
  const response = await ai.models.generateContent({
    model: process.env.GEMINI_MODEL,
    contents: "Return JSON: {\"status\":\"ok\"}",
    config: {
      responseMimeType: "application/json",
    },
  });

  console.log("Response:", response.text);
  console.log("Usage:", response.usageMetadata);
} catch (error) {
  console.error("Gemini error:", error.message);
  process.exitCode = 1;
}
