export function toTitleCase(str: string) {
    return str
        .replace(/_/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function capitalize(str: string) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
