export type StudioAlert = {
  title: string;
  message: string;
  tone: 'info' | 'warning' | 'error';
  details?: readonly string[];
};

export function StudioAlertPanel({ alert, live = true }: { alert: StudioAlert; live?: boolean }) {
  return (
    <div
      className={`error-panel alert ${alert.tone}`}
      role={live ? (alert.tone === 'info' ? 'status' : 'alert') : undefined}
    >
      <h3>{alert.title}</h3>
      <p>{alert.message}</p>
      {alert.details && alert.details.length > 0 ? (
        <ul>
          {alert.details.map((detail, index) => (
            <li key={index}>{detail}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
