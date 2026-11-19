export const btn =
  "rounded-md px-3 py-1.5 text-sm font-medium shadow-sm transition disabled:opacity-50 cursor-pointer";
export const primary = `${btn} bg-indigo-600 text-white hover:bg-indigo-500`;
export const secondary = `${btn} bg-white text-gray-900 ring-1 ring-gray-300 ring-inset hover:bg-gray-50`;
export const danger = `${btn} bg-white text-red-700 ring-1 ring-red-300 ring-inset hover:bg-red-50`;
export const textarea =
  "block w-full rounded-md p-2 text-sm ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none";
export const input =
  "block w-full rounded-md px-2 py-1 text-sm ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none";
export const badge = "rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset";
export const link = "hover:text-indigo-600 hover:underline";

export const fmtTime = (t: number) => new Date(t * 1000).toLocaleString();

/** Wraps an action: clears the error, sets busy, reports failures, then refreshes. */
export type Run = (fn: () => unknown) => () => Promise<void>;
