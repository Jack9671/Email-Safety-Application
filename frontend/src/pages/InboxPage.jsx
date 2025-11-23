import EmailInbox from "../components/EmailInbox";

export default function InboxPage({ apiStatus }) {
  return (
    <>
      <h2>📬 Email Inbox</h2>
      <EmailInbox apiStatus={apiStatus} />
    </>
  );
}
