import { t } from 'svelte-intl-precompile'
import { get } from 'svelte/store'

import { notify } from './toast'

export function copy(value: string) {
	window.navigator.clipboard.writeText(value)
	const msg = get(t)('common.copied_to_clipboard')
	notify.success(msg)
}

export function toArrayBuffer(view: ArrayBufferView): ArrayBuffer {
	const bytes = new Uint8Array(view.byteLength)
	bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength))
	return bytes.buffer
}

export function getCSSVariable(variable: string): string {
	if (typeof window === 'undefined') return ''
	return window.getComputedStyle(window.document.body).getPropertyValue(variable)
}
