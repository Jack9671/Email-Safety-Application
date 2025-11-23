import SpamChecker from "../components/SpamChecker";
import SpamResult from "../components/SpamResult";

export default function SpamPage({
  apiStatus,
  loading,
  error,
  spamResult,
  onCheck
}) {
  return (
    <>
      <h2><span className="icon">📧</span> Check Email for Spam</h2>
      <p className="card-description">
        Analyze email text using advanced BERT neural network.
      </p>

      {error && (
        <div className="alert alert-error">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      <SpamChecker onCheck={onCheck} loading={loading} apiStatus={apiStatus} />

      {spamResult && <SpamResult result={spamResult} />}
    </>
  );
}
