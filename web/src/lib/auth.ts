const TOKEN_KEY = "it4us_token";
const COOKIE_MAX_AGE = 8 * 60 * 60;

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo: no real login; return a fake token so the route guard allows going straight into the main UI.
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // Also write a cookie for the Next.js middleware to read server-side
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  // This installation has one shared login. Do not display unverified JWT claims
  // or the retired SOC identity from sessions issued before the change.
  getCurrentUser(): CurrentUser | null {
    if (!this.getToken()) return null;
    return { id: "1", name: "Guard4US", username: "IT4US VA", email: "", avatar: "", role: "admin" };
  },
};
