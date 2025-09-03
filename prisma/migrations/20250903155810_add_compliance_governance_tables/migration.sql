-- CreateEnum
CREATE TYPE "public"."ComplianceRequestType" AS ENUM ('DATA_ACCESS', 'DATA_RECTIFICATION', 'DATA_DELETION', 'DATA_PORTABILITY', 'PROCESSING_OBJECTION');

-- CreateEnum
CREATE TYPE "public"."RequestStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'REJECTED');

-- CreateEnum
CREATE TYPE "public"."ReviewStatus" AS ENUM ('PENDING', 'APPROVED', 'DENIED', 'ESCALATED');

-- CreateEnum
CREATE TYPE "public"."IncidentType" AS ENUM ('UNAUTHORIZED_ACCESS', 'SUSPICIOUS_LOGIN', 'MFA_BYPASS_ATTEMPT', 'BRUTE_FORCE_ATTACK', 'PRIVILEGE_ESCALATION', 'DATA_BREACH');

-- CreateEnum
CREATE TYPE "public"."IncidentSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "public"."IncidentStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED');

-- CreateTable
CREATE TABLE "public"."compliance_requests" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "public"."ComplianceRequestType" NOT NULL,
    "status" "public"."RequestStatus" NOT NULL DEFAULT 'PENDING',
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "data" JSONB,

    CONSTRAINT "compliance_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."access_reviews" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "reviewerId" TEXT,
    "dueDate" TIMESTAMP(3) NOT NULL,
    "status" "public"."ReviewStatus" NOT NULL DEFAULT 'PENDING',
    "completedAt" TIMESTAMP(3),
    "decision" JSONB,

    CONSTRAINT "access_reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."security_incidents" (
    "id" TEXT NOT NULL,
    "type" "public"."IncidentType" NOT NULL,
    "severity" "public"."IncidentSeverity" NOT NULL,
    "status" "public"."IncidentStatus" NOT NULL DEFAULT 'OPEN',
    "description" TEXT NOT NULL,
    "metadata" JSONB NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "assignedTo" TEXT,

    CONSTRAINT "security_incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."federated_users" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "lastSyncAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claims" JSONB NOT NULL,

    CONSTRAINT "federated_users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "federated_users_userId_key" ON "public"."federated_users"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "federated_users_providerId_externalId_key" ON "public"."federated_users"("providerId", "externalId");

-- AddForeignKey
ALTER TABLE "public"."compliance_requests" ADD CONSTRAINT "compliance_requests_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."access_reviews" ADD CONSTRAINT "access_reviews_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."access_reviews" ADD CONSTRAINT "access_reviews_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "public"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."federated_users" ADD CONSTRAINT "federated_users_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
