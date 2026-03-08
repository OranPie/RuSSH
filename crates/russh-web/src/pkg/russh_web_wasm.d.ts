/* tslint:disable */
/* eslint-disable */
/**
* @param {Function} status
* @param {Function} info
* @param {Function} error
* @param {Function} binary
*/
export function init_client(status: Function, info: Function, error: Function, binary: Function): void;
/**
* @param {string} mode
* @param {string} ws_url
* @param {string} host
* @param {number} port
* @param {string} user
* @param {string} password
* @param {string} identity_seed_hex
* @returns {Promise<void>}
*/
export function connect(mode: string, ws_url: string, host: string, port: number, user: string, password: string, identity_seed_hex: string): Promise<void>;
/**
* @param {Uint8Array} bytes
* @returns {Promise<void>}
*/
export function send_input(bytes: Uint8Array): Promise<void>;
/**
*/
export function disconnect(): void;
/**
* @returns {boolean}
*/
export function is_connected(): boolean;
/**
* @returns {boolean}
*/
export function is_connecting(): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly connect: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => number;
  readonly send_input: (a: number, b: number) => number;
  readonly is_connected: () => number;
  readonly is_connecting: () => number;
  readonly disconnect: () => void;
  readonly init_client: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly _dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h1a6d948286077fb3: (a: number, b: number, c: number) => void;
  readonly _dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hd09b53dc009eb7d4: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly wasm_bindgen__convert__closures__invoke2_mut__h2502ffd0f626fb35: (a: number, b: number, c: number, d: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
