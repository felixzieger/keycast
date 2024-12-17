import forms from "@tailwindcss/forms";
import typography from "@tailwindcss/typography";
import type { Config } from "tailwindcss";

export default {
    content: ["./src/**/*.{html,js,svelte,ts}"],
    darkMode: "class",
    theme: {
        fontFamily: {
            sans: ["system-ui", "-apple-system", "sans-serif"],
            mono: ["system-mono", "monospace"],
        },
        container: {
            center: true,
        },
        extend: {},
    },

    plugins: [typography, forms],
} satisfies Config;
