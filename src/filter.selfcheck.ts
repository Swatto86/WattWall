import assert from "node:assert/strict";
import { matches } from "./filter.ts";

assert.equal(matches("curl.exe", "C:\\Windows\\System32\\curl.exe", "", ""), true);
assert.equal(matches("curl.exe", "C:\\Windows\\System32\\curl.exe", "Microsoft", "curl"), true);
assert.equal(matches("curl.exe", "C:\\Windows\\System32\\curl.exe", "Microsoft", "MICROSOFT"), true);
assert.equal(matches("curl.exe", "C:\\Windows\\System32\\curl.exe", "Microsoft", "system32"), true);
assert.equal(matches("curl.exe", "C:\\Windows\\System32\\curl.exe", "Microsoft", "notepad"), false);
console.log("filter self-check ok");
