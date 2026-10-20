/*
 * AutoSeal task-semantic audit for one pinned public Matrix React SDK task.
 * This test is independently authored. It is not copied from the future fix.
 * It is injected only into a separate audit image, never the candidate image.
 */

import { AutoDiscoveryAction } from "matrix-js-sdk/src/autodiscovery";
import { M_AUTHENTICATION } from "matrix-js-sdk/src/client";

import AutoDiscoveryUtils from "../../src/utils/AutoDiscoveryUtils";

const home = {
    "m.homeserver": {
        state: AutoDiscoveryAction.SUCCESS,
        base_url: "https://matrix.example",
    },
};

const delegated = {
    issuer: "https://issuer.example/",
    authorizationEndpoint: "https://issuer.example/authorize",
    registrationEndpoint: "https://issuer.example/register",
    tokenEndpoint: "https://issuer.example/token",
    account: "https://issuer.example/account",
};

describe("AutoSeal delegated authentication audit", () => {
    it("preserves validated delegated authentication fields on success", () => {
        const discovery = {
            ...home,
            [M_AUTHENTICATION.stable!]: {
                state: AutoDiscoveryAction.SUCCESS,
                ...delegated,
                unrelatedSecret: "do-not-copy",
            },
        };
        const result = AutoDiscoveryUtils.buildValidatedConfigFromDiscovery(
            "matrix.example", discovery as any, true,
        );
        expect(result.delegatedAuthentication).toEqual(delegated);
    });

    it("does not trust a failed delegated authentication discovery", () => {
        const discovery = {
            ...home,
            [M_AUTHENTICATION.stable!]: {
                state: AutoDiscoveryAction.FAIL_ERROR,
                error: "untrusted issuer",
                ...delegated,
            },
        };
        const result = AutoDiscoveryUtils.buildValidatedConfigFromDiscovery(
            "matrix.example", discovery as any, true,
        );
        expect(result.delegatedAuthentication).toBeUndefined();
    });

    it("keeps delegated authentication optional", () => {
        const result = AutoDiscoveryUtils.buildValidatedConfigFromDiscovery(
            "matrix.example", home as any, true,
        );
        expect(result.delegatedAuthentication).toBeUndefined();
        expect(result.hsUrl).toBe("https://matrix.example");
    });
});
