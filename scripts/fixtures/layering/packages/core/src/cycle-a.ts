// expect: no-circular
import { b } from "./cycle-b.ts";

export const a: string = b;
