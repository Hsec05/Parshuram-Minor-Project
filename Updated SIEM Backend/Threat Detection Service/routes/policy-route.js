const express = require("express");
const router = express.Router();
const Policy = require("../models/policy");

// Create new policy
router.post("/", async (req, res) => {
  try {
    const policy = new Policy(req.body);
    await policy.save();
    res.status(201).json({ message: "Policy created", policy });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all policies
router.get("/", async (req, res) => {
  try {
    const policies = await Policy.find();
    res.json(policies);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single policy
router.get("/:id", async (req, res) => {
  try {
    const policy = await Policy.findById(req.params.id);
    if (!policy) return res.status(404).json({ error: "Policy not found" });
    res.json(policy);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update policy
router.put("/:id", async (req, res) => {
  try {
    const policy = await Policy.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!policy) return res.status(404).json({ error: "Policy not found" });
    res.json({ message: "Policy updated", policy });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete policy
router.delete("/:id", async (req, res) => {
  try {
    const policy = await Policy.findByIdAndDelete(req.params.id);
    if (!policy) return res.status(404).json({ error: "Policy not found" });
    res.json({ message: "Policy deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
