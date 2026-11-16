import Link from "next/link";

import { Card, PageHeader } from "@/components/ui";

export default function AssetNotFound() {
  return (
    <>
      <PageHeader title="Asset not found" />
      <Card>
        <p className="text-muted text-sm">
          This asset does not exist in the tenant you are working in. It may belong to another customer.{" "}
          <Link href="/noc/servers" className="text-primary hover:underline">
            Back to servers
          </Link>
        </p>
      </Card>
    </>
  );
}
