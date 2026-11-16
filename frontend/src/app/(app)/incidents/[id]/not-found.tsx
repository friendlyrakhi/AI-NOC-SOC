import Link from "next/link";

import { Card, PageHeader } from "@/components/ui";

export default function IncidentNotFound() {
  return (
    <>
      <PageHeader title="Incident not found" />
      <Card>
        <p className="text-muted text-sm">
          This incident does not exist in the tenant you are working in. It may belong to another customer.{" "}
          <Link href="/incidents" className="text-primary hover:underline">
            Back to incidents
          </Link>
        </p>
      </Card>
    </>
  );
}
