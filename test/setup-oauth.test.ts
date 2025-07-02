#!/usr/bin/env bun

import { describe, test, expect, afterEach, beforeEach, mock, spyOn } from "bun:test";
import { setupOAuthCredentials } from "../src/setup-oauth";
import { readFile, unlink, access } from "fs/promises";
import { join } from "path";
import { homedir } from "os";
import * as childProcess from "child_process";

describe("setupOAuthCredentials", () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    // Save original fetch
    originalFetch = global.fetch;
  });

  afterEach(async () => {
    // Restore original fetch
    global.fetch = originalFetch;

    // Clean up the credentials file after each test
    const credentialsPath = join(homedir(), ".claude", ".credentials.json");
    try {
      await unlink(credentialsPath);
    } catch (e) {
      // Ignore if file doesn't exist
    }
  });

  test("should create credentials file with correct structure", async () => {
    const credentials = {
      accessToken: "test-access-token",
      refreshToken: "test-refresh-token",
      expiresAt: "1234567890",
    };

    await setupOAuthCredentials(credentials);

    const credentialsPath = join(homedir(), ".claude", ".credentials.json");

    // Check file exists
    await access(credentialsPath);

    // Check file contents
    const content = await readFile(credentialsPath, "utf-8");
    const parsed = JSON.parse(content);

    expect(parsed).toEqual({
      claudeAiOauth: {
        accessToken: "test-access-token",
        refreshToken: "test-refresh-token",
        expiresAt: 1234567890,
        scopes: ["user:inference", "user:profile"],
      },
    });
  });

  test("should convert expiresAt string to number", async () => {
    const credentials = {
      accessToken: "test-access-token",
      refreshToken: "test-refresh-token",
      expiresAt: "9876543210",
    };

    await setupOAuthCredentials(credentials);

    const credentialsPath = join(homedir(), ".claude", ".credentials.json");
    const content = await readFile(credentialsPath, "utf-8");
    const parsed = JSON.parse(content);

    expect(typeof parsed.claudeAiOauth.expiresAt).toBe("number");
    expect(parsed.claudeAiOauth.expiresAt).toBe(9876543210);
  });

  test("should overwrite existing credentials file", async () => {
    // Create initial credentials
    await setupOAuthCredentials({
      accessToken: "old-token",
      refreshToken: "old-refresh",
      expiresAt: "1111111111",
    });

    // Overwrite with new credentials
    await setupOAuthCredentials({
      accessToken: "new-token",
      refreshToken: "new-refresh",
      expiresAt: "2222222222",
    });

    const credentialsPath = join(homedir(), ".claude", ".credentials.json");
    const content = await readFile(credentialsPath, "utf-8");
    const parsed = JSON.parse(content);

    expect(parsed.claudeAiOauth.accessToken).toBe("new-token");
    expect(parsed.claudeAiOauth.refreshToken).toBe("new-refresh");
    expect(parsed.claudeAiOauth.expiresAt).toBe(2222222222);
  });

  test("should create .claude directory if it doesn't exist", async () => {
    // This test is implicitly covered by the other tests, but we can verify
    // that the function doesn't fail even when the directory doesn't exist
    const credentials = {
      accessToken: "test-token",
      refreshToken: "test-refresh",
      expiresAt: "1234567890",
    };

    await setupOAuthCredentials(credentials);

    // Verify file was created
    const credentialsPath = join(homedir(), ".claude", ".credentials.json");
    await access(credentialsPath);
  });


  describe("Token refresh functionality", () => {
    test("should display warning when token is expiring and secrets_admin_pat is missing", async () => {
      const consoleSpy = spyOn(console, "warn").mockImplementation(() => {});
      
      // Set token to expire in 30 minutes (should trigger warning)
      const expiresAt = (Date.now() + 30 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "test-access-token",
        refreshToken: "test-refresh-token",
        expiresAt: expiresAt,
        // No secretsAdminPat provided
      };

      await setupOAuthCredentials(credentials);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("WARNING: OAuth token is expiring soon but SECRETS_ADMIN_PAT is not set!")
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("https://github.com/grll/claude-code-login/blob/main/README.md#prerequisites-setting-up-secrets_admin_pat")
      );

      consoleSpy.mockRestore();
    });

    test("should not display warning when token is not expiring", async () => {
      const consoleSpy = spyOn(console, "warn").mockImplementation(() => {});
      const consoleLogSpy = spyOn(console, "log").mockImplementation(() => {});
      
      // Set token to expire in 2 hours (should not trigger warning)
      const expiresAt = (Date.now() + 2 * 60 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "test-access-token",
        refreshToken: "test-refresh-token",
        expiresAt: expiresAt,
      };

      await setupOAuthCredentials(credentials);

      expect(consoleSpy).not.toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("Token is still valid")
      );

      consoleSpy.mockRestore();
      consoleLogSpy.mockRestore();
    });

    test("should attempt token refresh when secrets_admin_pat is provided and token is expiring", async () => {
      // Mock fetch to simulate successful token refresh
      const mockFetch = mock(() => 
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            access_token: "new-access-token",
            refresh_token: "new-refresh-token",
            expires_in: 3600,
          }),
        })
      );
      global.fetch = mockFetch as any;

      // Mock execSync to prevent actual execution but allow the test to proceed
      const execSyncSpy = spyOn(childProcess, "execSync").mockImplementation(() => {
        // Return empty buffer to simulate successful execution
        return Buffer.from("") as any;
      });
      const consoleLogSpy = spyOn(console, "log").mockImplementation(() => {});

      // Set token to expire in 30 minutes
      const expiresAt = (Date.now() + 30 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: expiresAt,
        secretsAdminPat: "test-pat-token",
      };

      await setupOAuthCredentials(credentials);

      // Verify fetch was called for token refresh
      expect(mockFetch).toHaveBeenCalledWith(
        "https://console.anthropic.com/v1/oauth/token",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: expect.stringContaining("refresh_token"),
        })
      );

      expect(consoleLogSpy).toHaveBeenCalledWith("✅ Token refreshed successfully!");

      // Verify credentials file contains new tokens
      const credentialsPath = join(homedir(), ".claude", ".credentials.json");
      const content = await readFile(credentialsPath, "utf-8");
      const parsed = JSON.parse(content);
      
      expect(parsed.claudeAiOauth.accessToken).toBe("new-access-token");
      expect(parsed.claudeAiOauth.refreshToken).toBe("new-refresh-token");

      execSyncSpy.mockRestore();
      consoleLogSpy.mockRestore();
    });

    test("should handle token refresh failure gracefully", async () => {
      // Mock fetch to simulate failed token refresh
      const mockFetch = mock(() => 
        Promise.resolve({
          ok: false,
          status: 400,
          text: () => Promise.resolve('{"error": "invalid_grant"}'),
        })
      );
      global.fetch = mockFetch as any;

      const consoleLogSpy = spyOn(console, "log").mockImplementation(() => {});
      const consoleErrorSpy = spyOn(console, "error").mockImplementation(() => {});

      // Set token to expire in 30 minutes
      const expiresAt = (Date.now() + 30 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "old-access-token",
        refreshToken: "invalid-refresh-token",
        expiresAt: expiresAt,
        secretsAdminPat: "test-pat-token",
      };

      await setupOAuthCredentials(credentials);

      expect(consoleLogSpy).toHaveBeenCalledWith("🔄 Token expired or expiring soon, refreshing...");
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("Token refresh failed: 400")
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith("❌ Failed to refresh token, using existing credentials");

      // Verify credentials file still contains old tokens
      const credentialsPath = join(homedir(), ".claude", ".credentials.json");
      const content = await readFile(credentialsPath, "utf-8");
      const parsed = JSON.parse(content);
      
      expect(parsed.claudeAiOauth.accessToken).toBe("old-access-token");
      expect(parsed.claudeAiOauth.refreshToken).toBe("invalid-refresh-token");

      consoleLogSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    });

    test("should handle GitHub secrets update failure", async () => {
      // Mock fetch to simulate successful token refresh
      const mockFetch = mock(() => 
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            access_token: "new-access-token",
            refresh_token: "new-refresh-token",
            expires_in: 3600,
          }),
        })
      );
      global.fetch = mockFetch as any;

      // Mock execSync to simulate GitHub secrets update failure
      const execSyncSpy = spyOn(childProcess, "execSync").mockImplementation(() => {
        throw new Error("GitHub CLI error");
      });
      const consoleErrorSpy = spyOn(console, "error").mockImplementation(() => {});

      // Set token to expire in 30 minutes
      const expiresAt = (Date.now() + 30 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: expiresAt,
        secretsAdminPat: "test-pat-token",
      };

      // Expect the function to throw due to GitHub CLI failure
      await expect(setupOAuthCredentials(credentials)).rejects.toThrow();

      execSyncSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    });

    test("should use correct environment variables when updating GitHub secrets", async () => {
      // Mock fetch to simulate successful token refresh
      const mockFetch = mock(() => 
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            access_token: "new-access-token",
            refresh_token: "new-refresh-token",
            expires_in: 3600,
          }),
        })
      );
      global.fetch = mockFetch as any;

      // Mock execSync to capture environment variables and simulate success
      const execSyncSpy = spyOn(childProcess, "execSync").mockImplementation(() => {
        return Buffer.from("") as any;
      });

      // Set token to expire in 30 minutes
      const expiresAt = (Date.now() + 30 * 60 * 1000).toString();
      
      const credentials = {
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: expiresAt,
        secretsAdminPat: "test-pat-token-12345",
      };

      await setupOAuthCredentials(credentials);

      // Verify execSync was called with correct environment
      expect(execSyncSpy).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          env: expect.objectContaining({
            GH_TOKEN: "test-pat-token-12345",
          }),
        })
      );

      execSyncSpy.mockRestore();
    });
  });
});
