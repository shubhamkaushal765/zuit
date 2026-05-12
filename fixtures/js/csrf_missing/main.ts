/**
 * Positive fixture for SEC008-csrf-missing: Express app with state-changing
 * handler, no CSRF middleware.
 */

import express from "express";

const app = express();
app.use(express.json());

app.post("/withdraw", (req, res) => {
    const amount = req.body.amount;
    const account = req.body.account;
    // perform the withdrawal
    res.json({ status: "ok", amount, account });
});

app.put("/profile", (req, res) => {
    const name = req.body.name;
    res.json({ status: "updated", name });
});

app.get("/balance", (req, res) => {
    res.json({ balance: 1000 });
});

app.listen(3000);
