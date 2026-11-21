// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./style.css";

import { App } from "./App.tsx";

const root = document.getElementById("root");
if (root === null) throw new Error("the page has no root");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
