import { AlertTriangle, ChevronRight, LoaderCircle, type LucideIcon } from "lucide-react";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { Link } from "react-router-dom";

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  icon?: ReactNode;
  busy?: boolean;
}

export function Button({
  variant = "secondary",
  icon,
  busy = false,
  children,
  className = "",
  disabled,
  ...props
}: ButtonProps) {
  return (
    <button
      className={`button button--${variant} ${className}`.trim()}
      disabled={disabled || busy}
      aria-busy={busy}
      {...props}
    >
      {busy ? <LoaderCircle className="spin" size={17} aria-hidden="true" /> : icon}
      <span>{children}</span>
    </button>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
  icon: LucideIcon;
}

export function IconButton({ label, icon: Icon, className = "", ...props }: IconButtonProps) {
  return (
    <button className={`icon-button ${className}`.trim()} aria-label={label} title={label} {...props}>
      <Icon size={18} aria-hidden="true" />
    </button>
  );
}

export function PageHeader({
  eyebrow,
  title,
  actions,
}: {
  eyebrow?: string;
  title: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <div className="eyebrow">{eyebrow}</div> : null}
        <h1>{title}</h1>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  action,
}: {
  icon: LucideIcon;
  title: string;
  action?: { label: string; to: string };
}) {
  return (
    <div className="empty-state">
      <Icon size={22} strokeWidth={1.5} aria-hidden="true" />
      <h2>{title}</h2>
      {action ? (
        <Link className="button button--primary" to={action.to}>
          <span>{action.label}</span>
          <ChevronRight size={17} aria-hidden="true" />
        </Link>
      ) : null}
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="error-state" role="alert">
      <AlertTriangle size={20} aria-hidden="true" />
      <span>{message}</span>
      {retry ? (
        <Button variant="ghost" onClick={retry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function LoadingRows({ count = 5 }: { count?: number }) {
  return (
    <div className="loading-rows" aria-label="Loading" aria-busy="true">
      {Array.from({ length: count }, (_, index) => (
        <div className="skeleton-row" key={index} />
      ))}
    </div>
  );
}

export function InlineNotice({
  tone = "neutral",
  icon,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement> & {
  tone?: "neutral" | "warning" | "danger" | "success";
  icon?: ReactNode;
}) {
  return (
    <div className={`inline-notice inline-notice--${tone}`} {...props}>
      {icon}
      <span>{children}</span>
    </div>
  );
}

export function FieldError({ message }: { message: string | undefined }) {
  return message ? (
    <span className="field-error" role="alert">
      {message}
    </span>
  ) : null;
}
