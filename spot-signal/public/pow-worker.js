async function hasLeadingZeroBits(bytes, difficultyBits) {
  const wholeBytes = Math.floor(difficultyBits / 8);
  for (let index = 0; index < wholeBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  const remainingBits = difficultyBits % 8;
  return remainingBits === 0 || (bytes[wholeBytes] >>> (8 - remainingBits)) === 0;
}

self.onmessage = async event => {
  const { challenge, difficultyBits } = event.data ?? {};
  if (typeof challenge !== "string" || !Number.isInteger(difficultyBits) || difficultyBits < 0 || difficultyBits > 24) {
    self.postMessage({ type: "error", message: "Invalid challenge" });
    return;
  }
  const encoder = new TextEncoder();
  for (let nonce = 0; nonce < Number.MAX_SAFE_INTEGER; nonce += 1) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`${challenge}:${nonce}`));
    if (await hasLeadingZeroBits(new Uint8Array(digest), difficultyBits)) {
      self.postMessage({ type: "solved", nonce: String(nonce) });
      return;
    }
    if ((nonce & 2047) === 2047) {
      self.postMessage({ type: "progress", attempts: nonce + 1 });
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
  self.postMessage({ type: "error", message: "Could not find a proof" });
};
