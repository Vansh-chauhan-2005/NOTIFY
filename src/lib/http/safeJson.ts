export async function safeReadJson<T = any>(res: Response): Promise<T & { success?: boolean; message?: string }> {
  const text = await res.text();
  if (!text) {
    return {
      success: false,
      message: `Server returned an empty response (HTTP ${res.status}).`,
    } as T & { success?: boolean; message?: string };
  }

  try {
    return JSON.parse(text);
  } catch {
    const looksLikeHtml = text.trimStart().startsWith('<');
    return {
      success: false,
      message: looksLikeHtml
        ? `Server returned an HTML page instead of JSON (HTTP ${res.status}). Make sure the backend server is running on port 3000.`
        : `Invalid JSON response from server (HTTP ${res.status}).`,
    } as T & { success?: boolean; message?: string };
  }
}
