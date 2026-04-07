export default function PageVideoBackdrop({ className = '' }) {
  return (
    <div className={className} aria-hidden="true">
      <video autoPlay muted loop playsInline>
        <source src="/assets/video/hero-background.mp4" type="video/mp4" />
      </video>
      <div className="page-video-overlay" />
      <div className="page-video-fade" />
    </div>
  );
}