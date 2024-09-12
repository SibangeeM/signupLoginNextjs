"use server";

import { createAuthSession, destroySession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser, getUserByEmail } from "@/lib/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  //validation
  let errors = {};
  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address.";
  }
  if (password.trim().length < 8) {
    errors.password = "Password must be aleast 8 characters long.";
  }
  if (Object.keys(errors).length > 0) {
    return {
      errors: errors,
    };
  }

  // store it in the database
  const hashedPassword = hashUserPassword(password);
  try {
    const id = createUser(email, hashedPassword);
    createAuthSession(id);
    redirect("/training");
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "It seems like an account for the chosen email already exits",
        },
      };
    }
    throw error;
  }
}
export async function login(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");
  const existingUser = getUserByEmail(email);
  if (!existingUser) {
    return {
      errors: {
        email: "Could not authenticate user, please check your credentials.",
      },
    };
  }
  if (!verifyPassword(existingUser.password, password)) {
    return {
      errors: {
        email: "Could not authenticate user, please check your credentials.",
      },
    };
  }
  createAuthSession(existingUser.id);
  redirect("/training");
}

export async function auth(mode, prevState, formData) {
  if (mode === "login") {
    return login(prevState, formData);
  }
  return signup(prevState, formData);
}


export async function logout(){
    await destroySession();
    redirect("/");
}