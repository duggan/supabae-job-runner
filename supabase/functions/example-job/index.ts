// Follow this setup guide to integrate the Deno language server with your editor:
// https://deno.land/manual/getting_started/setup_your_environment
// This enables autocomplete, go to definition, etc.

// Setup type definitions for built-in Supabase Runtime APIs

import "@supabase/edge-runtime";
import { createClient } from "@supabase/supabase-js";

Deno.serve(async (req) => {
  const { data } = await req.json();

  // X-Job and X-Correlation-ID are used as part of the Job Runner system.
  const correlationId = req.headers.get("X-Correlation-ID");
  const isJob = req.headers.get("X-Job");

  if (!correlationId || !isJob) {
    console.error("Missing required Job Runner headers");
    return new Response(
      JSON.stringify({
        error: "Missing required Job Runner headers",
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  console.log("X-Correlation-ID: ", correlationId);
  console.log("X-Job", isJob);

  const authHeader = req.headers.get("Authorization")!;
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_ANON_KEY") ?? "",
    { global: { headers: { Authorization: authHeader } } },
  );
  const token = authHeader.replace("Bearer ", "");
  const {
    data: { user },
  } = await supabase.auth.getUser(token);

  /**
   * Only run if we have a user context
   */
  if (!user?.email) {
    console.error("No valid user token received");
    return new Response(
      JSON.stringify({
        error: "Unauthorized",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "X-Correlation-ID": correlationId,
          "X-Job": isJob,
        },
      },
    );
  }

  // Do something
  const success = !!data;

  if (success) {
    console.log("Successfully processed request");
    return new Response(null, {
      status: 204,
      headers: {
        "Content-Type": "application/json",
        "X-Correlation-ID": correlationId,
        "X-Job": isJob,
      },
    });
  }

  console.error("Failed to process request");
  return new Response(null, {
    status: 500,
    headers: {
      "Content-Type": "application/json",
      "X-Correlation-ID": correlationId,
      "X-Job": isJob,
    },
  });
});
