import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { getSupabaseClient } from "@/lib/supabase/serverClient";
import { getApiErrorMessage, normalizeSupabaseError } from "@/lib/api/errors";

const AuthSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("signup"),
    email: z.string().email(),
    password: z.string().min(8),
    fullName: z.string().min(1).max(120).optional(),
  }),
  z.object({
    action: z.literal("login"),
    email: z.string().email(),
    password: z.string().min(8),
  }),
  z.object({
    action: z.literal("refresh"),
    refresh_token: z.string().min(10),
  }),
]);

export async function POST(req: NextRequest) {
  const supabase = getSupabaseClient(req, "anon");

  let parsedBody;
  try {
    const body = await req.json();
    parsedBody = AuthSchema.parse(body);
  } catch (err) {
    if (err instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid request body", details: err.flatten() },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Invalid JSON payload" },
      { status: 400 },
    );
  }

  try {
    if (parsedBody.action === "signup") {
      const { email, password, fullName } = parsedBody;

      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: fullName ? { full_name: fullName } : undefined,
        },
      });

      if (error) {
        const { body, status } = normalizeSupabaseError(error);
        return NextResponse.json(body, { status });
      }

      return NextResponse.json(
        {
          user: data.user,
          session: data.session,
        },
        { status: 201 },
      );
    }

    if (parsedBody.action === "login") {
      const { email, password } = parsedBody;

      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        const { body, status } = normalizeSupabaseError(error);
        return NextResponse.json(body, { status });
      }

      return NextResponse.json(
        {
          user: data.user,
          session: data.session,
        },
        { status: 200 },
      );
    }

    if (parsedBody.action === "refresh") {
      const { refresh_token } = parsedBody;

      const { data, error } = await supabase.auth.refreshSession({
        refresh_token,
      });

      if (error) {
        const { body, status } = normalizeSupabaseError(error);
        return NextResponse.json(body, { status });
      }

      return NextResponse.json(
        {
          user: data.user,
          session: data.session,
        },
        { status: 200 },
      );
    }

    return NextResponse.json(
      { error: "Unsupported auth action" },
      { status: 400 },
    );
  } catch (err) {
    console.error(err);
    const { error, details } = getApiErrorMessage(err);
    const isFetchFailed =
      err instanceof TypeError && (err as Error).message === "fetch failed";
    return NextResponse.json(
      details ? { error, details } : { error },
      { status: isFetchFailed ? 502 : 500 },
    );
  }
}

