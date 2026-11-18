import test from "node:test";
import assert from "node:assert/strict";
import {detectIncidents, normalizeEvent, parseEvents} from "../analyzer.js";

const event = (id, minute, user="alex", outcome="failure", ip="192.0.2.10", country="GH") => ({id,timestamp:`2026-01-01T08:${String(minute).padStart(2,"0")}:00Z`,source_ip:ip,username:user,outcome,country});

test("normalizes dates and fields",()=>assert.equal(normalizeEvent(event("a",0)).timestamp,"2026-01-01T08:00:00.000Z"));
test("rejects invalid outcome",()=>assert.throws(()=>normalizeEvent({...event("a",0),outcome:"maybe"}),/outcome/));
test("parses a JSON event array",()=>assert.equal(parseEvents(JSON.stringify([event("a",0)])).length,1));
test("parses basic CSV",()=>assert.equal(parseEvents("timestamp,source_ip,username,outcome,country\n2026-01-01T08:00:00Z,192.0.2.1,a,success,GH").length,1));
test("detects five failures in ten minutes",()=>{const r=detectIncidents([0,1,2,3,4].map(i=>event(`e${i}`,i)));assert.ok(r.incidents.some(i=>i.type==="brute_force"));});
test("detects a password spray across four users",()=>{const r=detectIncidents(["a","b","c","d"].map((u,i)=>event(`e${i}`,i,u)));assert.ok(r.incidents.some(i=>i.type==="password_spray"));});
test("detects a success after repeated failures",()=>{const items=[0,1,2,3].map(i=>event(`e${i}`,i));items.push(event("ok",4,"alex","success"));const r=detectIncidents(items);assert.ok(r.incidents.some(i=>i.type==="success_after_failures"));});
test("labels rapid country changes as a heuristic",()=>{const r=detectIncidents([event("a",0,"alex","success","192.0.2.1","GH"),event("b",20,"alex","success","203.0.113.1","GB")]);const found=r.incidents.find(i=>i.type==="rapid_country_change");assert.match(found.detail,/does not prove travel/);});

