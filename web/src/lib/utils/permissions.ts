import type {
    AllowedKindsConfig,
    ContentFilterConfig,
    Permission,
} from "$lib/types";
import { capitalize } from "./strings";

export function readablePermissionConfig(permission: Permission) {
    switch (permission.identifier) {
        case "allowed_kinds":
            return Object.entries(permission.config as AllowedKindsConfig).map(
                ([key, value]) => {
                    if (value === null) {
                        return `${capitalize(key)}: All kinds allowed`;
                    }
                    return `${capitalize(key)}: ${(value as number[]).join(", ")}`;
                },
            );
        case "content_filter":
            return `Blocked words: ${(permission.config as ContentFilterConfig).blocked_words?.join(", ")}`;
        default:
            return JSON.stringify(permission.config, null, 2);
    }
}
