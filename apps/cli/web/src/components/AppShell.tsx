import { useQuery } from "@tanstack/react-query";
import { Activity, FlaskConical, Menu, Settings2, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import bannerUrl from "../../../../../assets/shannon-banner.png";
import { api } from "../lib/api";

const navigation = [
  { to: "/runs", label: "Runs", icon: Activity },
  { to: "/assessments/new", label: "New assessment", icon: FlaskConical },
  { to: "/profiles", label: "Profiles", icon: Settings2 },
];

export function AppShell({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const bootstrapQuery = useQuery({ queryKey: ["bootstrap"], queryFn: () => api.bootstrap() });

  useEffect(() => setMobileOpen(false), [location.pathname]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="mobile-header">
        <img src={bannerUrl} alt="Shannon" className="mobile-brand" />
        <button
          className="icon-button"
          type="button"
          aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={mobileOpen}
          onClick={() => setMobileOpen((value) => !value)}
        >
          {mobileOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </button>
      </header>

      <aside className={`sidebar${mobileOpen ? " sidebar--open" : ""}`} aria-label="Primary navigation">
        <div className="brand-block">
          <img src={bannerUrl} alt="Shannon" className="brand-image" />
          <span className="brand-edition">Operator</span>
        </div>
        <nav className="primary-nav">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-link${isActive ? " nav-link--active" : ""}`}
            >
              <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="connection-state" aria-live="polite">
            <span
              className={`connection-dot${bootstrapQuery.isSuccess ? " connection-dot--online" : ""}`}
              aria-hidden="true"
            />
            <span>{bootstrapQuery.isSuccess ? "Local service online" : "Connecting to service"}</span>
          </div>
          {bootstrapQuery.data ? (
            <div className="build-meta">
              <span>v{bootstrapQuery.data.version}</span>
              <span>{bootstrapQuery.data.secretStore.label}</span>
            </div>
          ) : null}
        </div>
      </aside>

      {mobileOpen ? (
        <button
          className="nav-scrim"
          type="button"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
        />
      ) : null}

      <main id="main-content" className="main-content" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
