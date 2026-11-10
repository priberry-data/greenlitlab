// GET /api/questions: the seven things only the owner knows, with the fact and the fix prompt for each answer.
// Answers are shown in the visitor's browser and never sent back here.
import { QUESTIONS } from "../../src/questions.mjs";

export const onRequestGet = () => new Response(JSON.stringify(QUESTIONS), { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=3600" } });
