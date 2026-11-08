import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The last result for each site is kept on this machine (ids, titles and score only: no keys, no data),
// so running the check again shows what the fixes changed.
const HISTORY = () => path.join(process.env.GREENLIT_HOME ?? path.join(os.homedir(), ".greenlit"), "sites");
const historyFile = (origin, mine, dir) => path.join(dir, `${new URL(origin).host.replace(/[^\w.-]/g, "_")}${mine ? ".mine" : ""}.json`);

export function loadLast(origin, mine, dir = HISTORY()) {
  try {
    return JSON.parse(fs.readFileSync(historyFile(origin, mine, dir), "utf8"));
  } catch {
    return null;
  }
}

export function saveRun(result, dir = HISTORY()) {
  const slim = { at: new Date().toISOString(), score: result.score, grade: result.grade, findings: result.findings.map(({ id, severity, title }) => ({ id, severity, title })) };
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(historyFile(result.url, result.mine, dir), JSON.stringify(slim, null, 2) + "\n");
  } catch {}
  return slim;
}

