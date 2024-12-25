

export default {
    port: process.env.PORT || 3000,
    db: process.env.DATABASE_URL || "postgres://postgres:password@database/cryptochest",
}