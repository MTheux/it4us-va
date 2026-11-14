const TOKEN_KEY = "it4us_token";
const COOKIE_MAX_AGE = 8 * 60 * 60;
const USER_KEY = "guard4us_current_user";
const SSO_SENTINEL = "sso-cookie";

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
    return this.isSSO() ? SSO_SENTINEL : (localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null));
  },

  isSSO(): boolean {
    return typeof document !== "undefined" && document.cookie.split("; ").some((item) => item === "guard4us_sso=1");
  },

  acceptSSO(): void {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
  },

  setCurrentUser(user: CurrentUser): void {
    sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // Also write a cookie for the Next.js middleware to read server-side
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
    document.cookie = "guard4us_sso=; path=/; max-age=0";
  },

  // This installation has one shared login. Do not display unverified JWT claims
  // or the retired SOC identity from sessions issued before the change.
  getCurrentUser(): CurrentUser | null {
    if (!this.getToken()) return null;
    try {
      const saved = sessionStorage.getItem(USER_KEY);
      if (saved) return JSON.parse(saved) as CurrentUser;
    } catch { /* A corrupt display cache never grants a session. */ }
    return { id: "1", name: "Equipe IT4US", username: "IT4US VA", email: "", avatar: "", role: "admin" };
  },
};
