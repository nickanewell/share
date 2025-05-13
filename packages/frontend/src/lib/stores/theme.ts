import { derived } from 'svelte/store'
import { theme } from '$lib/ui/ThemeToggle.svelte'

export const themeLogo = derived(theme, ($theme) => {
    // For auto theme, we'll use the system preference
    if ($theme === 'auto') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
        return prefersDark ? '/logo-dark.svg' : '/logo-light.svg'
    }
    // For explicit themes, use the corresponding logo
    return $theme === 'dark' ? '/logo-dark.svg' : '/logo-light.svg'
}) 