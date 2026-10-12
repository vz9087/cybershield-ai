import "dotenv/config";
import { seedAdminAccounts, INITIAL_ADMINS } from "./db";

async function main() {
  console.log("=================================================");
  console.log(" CyberShield AI — Administrator Account Seeder   ");
  console.log("=================================================");
  console.log("Configuring the 3 designated administrator identities:");
  for (const admin of INITIAL_ADMINS) {
    console.log(` - ${admin.name} <${admin.email}> [Role: ADMIN]`);
  }

  const result = await seedAdminAccounts();
  console.log("-------------------------------------------------");
  console.log(`Initialization complete: ${result.created} created, ${result.existing} already active.`);
  console.log("Admin accounts are verified and secured in the database.");
  console.log("=================================================");
}

main().catch(err => {
  console.error("Seeding failed:", err);
  process.exit(1);
});
