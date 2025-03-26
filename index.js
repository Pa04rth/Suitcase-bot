import { useState } from "react";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import { mnemonicToSeed } from "bip39";
import { derivePath } from "ed25519-hd-key";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
export default defineConfig({
  plugins: [react(), nodePolyfills()],
});
import { generateMnemonic } from "bip39";
import TelegramBot from "node-telegram-bot-api";
import axios from "axios";
import bcrypt from "bcrypt";
import crypto from "crypto";
import dotenv from "dotenv";
import mongoose from "mongoose";
import {
  Connection,
  clusterApiUrl,
  Keypair,
  LAMPORTS_PER_SOL,
  Transaction,
  SystemProgram,
  sendAndConfirmTransaction,
  VersionedTransaction,
} from "@solana/web3.js";
import fetch from "cross-fetch";
import { Wallet } from "@project-serum/anchor";
import bs58 from "bs58";

dotenv.config();
//Here the token is stored in the environment variables given by BotFather
const token = process.env.BOT_TOKEN;

//Creating a bot which uses 'polling' to fetch new messages
const bot = new TelegramBot(token, { polling: true });
bot.on("polling_error", (error) => {
  console.error("Polling error:", error);
});
const userSteps = {}; // Object to store user steps
const userData = {}; // Object to store user data
//Connecting to database
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "Connection error:"));
db.once("open", () => console.log("Connected to MongoDB Atlas"));

// Encryption functions- to encrypt and decrypt the private key
const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(process.env.ENCRYPTION_KEY),
    iv
  );
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
};

const decrypt = (text) => {
  const [iv, encryptedText] = text.split(":");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(process.env.ENCRYPTION_KEY),
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(Buffer.from(encryptedText, "hex"));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

// User Schema
const userSchema = new mongoose.Schema({
  userId: { type: Number, required: true, unique: true }, // Telegram User ID
  passwordHash: { type: String, required: true }, // Hashed password
  walletInfo: {
    address: {
      type: [String], // Allow an array of strings
      required: true,
    },
    privateKey: {
      type: [String], // Allow an array of strings
      required: true,
    },
  },
});

const User = mongoose.model("User", userSchema);

//Default Rpc Url
const mainnet_rpcUrl =
  "https://solana-mainnet.g.alchemy.com/v2/3nQAXG7Be1pxPFKFiZnaRtt_0lL481ZD"; // Replace with your Solana RPC endpoint or any other blockchain RPC

const devnet_rpcUrl = "https://api.devnet.solana.com"; // Replace with your Solana RPC endpoint or any other blockchain RPC

// To create a solana wallet .....
// export function SolanaWallet({ mnemonic }) {
//   const [currentIndex, setCurrentIndex] = useState(0);
//   const [publicKeys, setPublicKeys] = useState([]);
//   const seed = mnemonicToSeed(mnemonic);
//   const path = `m/44'/501'/${currentIndex}'/0'`;
//   const derivedSeed = derivePath(path, seed.toString("hex")).key;
//   const secret = nacl.sign.keyPair.fromSeed(derivedSeed).secretKey;
//   const keypair = Keypair.fromSecretKey(secret);
//   setCurrentIndex(currentIndex + 1);
//   setPublicKeys([...publicKeys, keypair.publicKey]);
//   setPrivateKeys([...privateKeys, secret.toString("hex")]); // Convert private key to hex

//   return {
//     publicKeys: publicKeys.map((p) => p.toBase58()), // Array of wallet addresses
//     privateKeys: privateKeys, // Array of private keys
//   };
// }
export function SolanaWallet({ mnemonic }) {
  let currentIndex = 0;
  const publicKeys = [];
  const privateKeys = [];
  const seed = mnemonicToSeed(mnemonic);

  function generateNextKeypair() {
    const path = `m/44'/501'/${currentIndex}'/0'`;
    const derivedSeed = derivePath(path, seed.toString("hex")).key;
    const secret = nacl.sign.keyPair.fromSeed(derivedSeed).secretKey;
    const keypair = Keypair.fromSecretKey(secret);

    publicKeys.push(keypair.publicKey);
    privateKeys.push(secret.toString("hex"));
    currentIndex++;
  }

  // Generate the first keypair (index 0)
  generateNextKeypair();

  return {
    publicKeys: publicKeys.map((p) => p.toBase58()),
    privateKeys: [...privateKeys],
    getNextWallet: function () {
      generateNextKeypair();
      return {
        publicKeys: this.publicKeys,
        privateKeys: this.privateKeys,
      };
    },
  };
}

//Writing logic for sending the SOLs-
const sendSOL = async (
  senderAddress,
  publicKey,
  amount,
  privateKey,
  rpc_Type
) => {
  let connection;
  if (rpc_Type === "Mainnet") {
    connection = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");
  } else if (rpc_Type === "Devnet") {
    connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  } else {
    throw new Error("Invalid rpc_Type. Use 'Mainnet' or 'Devnet'.");
  }
  // Establish connection to the Solana network (mainnet-beta)
  // const connection = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");
  const lamports = amount * LAMPORTS_PER_SOL;
  // Create a transaction
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: senderAddress, // Sender's public key
      toPubkey: publicKey, // Recipient's public key
      lamports, // Amount to send in lamports
    })
  );
  // 2. Sender's private key (as Uint8Array) - replace with your sender's private key
  const senderSecretKey = Uint8Array.from(privateKey);

  // 3. Create sender wallet (Keypair) from the private key
  const senderWallet = Keypair.fromSecretKey(senderSecretKey);
  // Send and confirm the transaction
  const signature = await sendAndConfirmTransaction(connection, transaction, [
    senderWallet,
  ]);

  console.log("Transaction successful with signature:", signature);
  return signature;
};

// Function to receive airdrop on Devnet
const receiveAirdrop = async (publicKey) => {
  const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  try {
    // Request an airdrop of 1 SOL
    const airdropSignature = await connection.requestAirdrop(
      publicKey,
      1 * LAMPORTS_PER_SOL
    );

    // Confirm the airdrop transaction
    await connection.confirmTransaction(airdropSignature);

    return {
      airdropResult: true,
      success: true,
      message: `Airdrop successful! You've received 1 SOL in your wallet: ${publicKey}. Check your balance on the Solana Explorer.`,
    };
  } catch (error) {
    console.error("Airdrop failed:", error);
    return {
      success: false,
      message:
        "Airdrop failed. Please try again later or check your wallet address.",
    };
  }
};

const swapTokens = async (
  tokenA,
  tokenB,
  amount,
  slippagePercentage,
  privateKey
) => {
  const connection = new Connection(
    "https://solana-mainnet.g.alchemy.com/v2/3nQAXG7Be1pxPFKFiZnaRtt_0lL481ZD"
  );

  // Convert private key to Keypair
  const keypair = Keypair.fromSecretKey(bs58.decode(privateKey));
  const wallet = new Wallet(keypair);

  // Define mint addresses
  let input_Mint, output_Mint;

  // Mapping token symbols to mint addresses
  const tokenMints = {
    SOL: "So11111111111111111111111111111111111111112",
    USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    USDT: "Es9vMFrzaCER9hymBdddbMbmD7rU4utBfG7b1p5Ab4ms",
  };

  if (tokenMints[tokenA]) input_Mint = tokenMints[tokenA];
  if (tokenMints[tokenB]) output_Mint = tokenMints[tokenB];

  if (!input_Mint || !output_Mint) {
    throw new Error("Invalid token symbols provided.");
  }

  // Convert amount to lamports
  const tokenDecimals = {
    SOL: 9,
    USDC: 6,
    USDT: 6,
  };

  const decimals = tokenDecimals[tokenA] || 6; // Default to 6 decimals
  const amountLamports = amount * 10 ** decimals;

  // Fetch quote
  const url = `https://quote-api.jup.ag/v6/quote?inputMint=${input_Mint}&outputMint=${output_Mint}&amount=${amountLamports}&slippageBps=50`;
  const response = await fetch(url);
  const quoteResponse = await response.json();

  console.log({ quoteResponse });

  // Calculate dynamic slippage
  const dynamicSlippageBps = slippagePercentage * 100;

  // Get swap transaction
  const { swapTransaction } = await (
    await fetch("https://quote-api.jup.ag/v6/swap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quoteResponse,
        userPublicKey: wallet.publicKey.toString(),
        wrapAndUnwrapSol: true,
        dynamicSlippage: { maxBps: dynamicSlippageBps },
      }),
    })
  ).json();

  // Deserialize the transaction
  const swapTransactionBuf = Buffer.from(swapTransaction, "base64");
  let transaction = VersionedTransaction.deserialize(swapTransactionBuf);
  console.log(transaction);

  // Sign the transaction
  transaction.sign([wallet.payer]);

  // Execute the transaction
  const rawTransaction = transaction.serialize();
  const txid = await connection.sendRawTransaction(rawTransaction, {
    skipPreflight: true,
    maxRetries: 2,
  });

  await connection.confirmTransaction(txid);
  console.log(`Transaction Successful: https://solscan.io/tx/${txid}`);
};

// Function to fetch account details using RPC call
async function fetchAccountDetails(publicKey, privateKey, rpcUrl) {
  let rpcType;
  if (
    rpcUrl ===
    "https://solana-mainnet.g.alchemy.com/v2/3nQAXG7Be1pxPFKFiZnaRtt_0lL481ZD"
  ) {
    rpcType = "Mainnet";
  } else if (rpcUrl === "https://api.devnet.solana.com") {
    rpcType = "Devnet";
  }
  const requestData = {
    jsonrpc: "2.0",
    id: 1,
    method: "getBalance",
    params: [
      publicKey, // Pass the public key
      { encoding: "jsonParsed" }, // Set encoding format, could be 'base58' or 'jsonParsed' based on requirements
    ],
  };

  try {
    const response = await axios.post(rpcUrl, requestData, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    // Check if the response is successful and account data is available
    if (response.data.result) {
      console.log("Account details:", response.data.result);
      bot
        .sendMessage(
          chatId,
          `Your Wallet Info:\n\n` +
            "💡*RPC*: " +
            rpcType +
            "\n" +
            `🔑 *Public Key:* \`${publicKey}\`\n` +
            `💰 *Current Balance:* ${response.data.result} SOL\n\n` +
            "⭐  To add a new wallet - /addWallet\n\n" +
            `Please choose one of the actions below:`,
          {
            parse_mode: "Markdown", // To format the message nicely
            reply_markup: {
              inline_keyboard: [
                [{ text: "🔄 Send", callback_data: "send" }],
                [{ text: "💸 Receive", callback_data: "receive" }],
                [{ text: "💱 Swap", callback_data: "swap" }],
                [{ text: "⚙️ Settings", callback_data: "settings" }],
              ],
            },
          }
        )
        .then(() => {
          bot.on("callback_query", (callbackQuery) => {
            const data = callbackQuery.data;
            const chatId = callbackQuery.message.chat.id;

            if (data === "send") {
              if (response.data.result > 0) {
                bot
                  .sendMessage(
                    chatId,
                    "You've selected Send. Please enter the recipient's wallet address and amount in SOL, separated by a comma. Example: `recipientAddress, 2.5`"
                  )
                  .then(() => {
                    bot.on("message", async (msg) => {
                      const userMessage = msg.text.split(",");
                      const recipientAddress = userMessage[0].trim();
                      const amountToSend = parseFloat(userMessage[1]);

                      // Add the logic for sending SOL using RPC here
                      const transactionSignature = await sendSOL(
                        publicKey,
                        recipientAddress,
                        amountToSend,
                        privateKey,
                        rpcType
                      );
                      if (transactionSignature) {
                        bot.sendMessage(
                          chatId,
                          `🎉 Transaction successful! Signature: ${transactionSignature}.To go back to the main wallet page, type /login`
                        );
                      } else {
                        bot.sendMessage(
                          chatId,
                          "❌ Transaction failed. Please try again. To go back to the main wallet page, type /login"
                        );
                      }
                    });
                  });
              } else {
                bot.sendMessage(
                  chatId,
                  "You don't have enough balance to send"
                );
              }
              // Handle 'Send' action
            } else if (data === "receive") {
              if (rpcType === "Mainnet") {
                bot.sendMessage(
                  chatId,
                  `Your wallet address to receive SOL is:\n\`${publicKey}\`\nYou can share this address to receive funds. To go back to the main wallet page, type /login`
                );
              } else if (rpcType === "Devnet") {
                bot
                  .sendMessage(
                    chatId,
                    "You are on Devnet, you can get free 1 SOL from the faucet to test your wallet, Just type -🛩️  /airdrop"
                  )
                  .then(() => {
                    bot.onText(/\/airdrop/, async (msg) => {
                      const airdropResult = await receiveAirdrop(publicKey);
                      if (airdropResult) {
                        bot.sendMessage(
                          chatId,
                          `🎉 Airdrop successful! , Type /login to go to main wallet page `
                        );
                      } else {
                        bot.sendMessage(
                          chatId,
                          `❌ Airdrop failed! , Type /login to go to main wallet page `
                        );
                      }
                    });
                  });
              }

              // You can add QR code generation logic here if needed
            } else if (data === "swap") {
              //Handle 'Swap' action
              bot
                .sendMessage(
                  chatId,
                  "You've selected Swap. Please enter the details of the tokens you want to swap.\n\n Example: `tokenA, tokenB, amount,slippagePercentage\n\n Write SOL-Solana\nUSDC-USDC\nUSDT-Tether\n\n `"
                )
                .then(() => {
                  bot.on("message", async (msg) => {
                    const userMessage = msg.text.split(",");
                    const tokenA = userMessage[0].trim();
                    const tokenB = userMessage[1].trim();
                    const amountToSwap = parseFloat(userMessage[2]);
                    const slippagePercentage = parseFloat(userMessage[3]);
                    // Add the logic for swapping tokens here using your swap logic
                    await swapTokens(
                      tokenA,
                      tokenB,
                      amountToSwap,
                      slippagePercentage,
                      privateKey
                    );

                    bot.sendMessage(
                      chatId,
                      `✅ Successfully swapped ${amountToSwap} ${tokenA} for ${tokenB}`
                    );
                  });
                });
            } else if (data === "settings") {
              bot.sendMessage(chatId, "⚙️**Settings**\n\n ", {
                reply_markup: {
                  inline_keyboard: [
                    [
                      {
                        text: "🗝️Change Password",
                        callback_data: "change_password",
                      },
                    ],
                    [
                      {
                        text: "🛜Change RPC Connection",
                        callback_data: "devnet",
                      },
                    ],

                    [{ text: "✈️Show private key ", callback_data: "show" }],
                  ],
                },
              });
            }
          });
        });
    } else {
      console.log("No account found or invalid public key");
    }
  } catch (error) {
    console.error("Error fetching account details:", error.message);
  }
}

bot.onText(/\/login/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id; // Retrieve the user ID
  // Fetch the user from the database
  bot
    .sendMessage(chatId, "Please enter your password to login:", {
      reply_markup: {
        force_reply: true,
      },
    })
    .then(() => {
      bot.on("message", async (msg) => {
        const chatId = msg.chat.id;
        const password = msg.text; // Get user input
        const userId = msg.from.id; // Retrieve the user ID
        try {
          const user = await User.findOne({ userId: userId });
          if (!user) {
            return bot.sendMessage(
              chatId,
              "User not found. Please create a new wallet."
            );
          }
          // Compare the password with the hashed password
          const passwordMatch = await bcrypt.compare(
            password,
            user.passwordHash
          );

          if (passwordMatch) {
            const decryptedPrivateKey = decrypt(user.walletInfo.privateKey);
            // If password matches, return the public key
            return bot.sendMessage(chatId, `Login successful!`).then(() => {
              fetchAccountDetails(
                user.walletInfo.address,
                decryptedPrivateKey.map((str) => Number(str)),
                mainnet_rpcUrl
              );
            });
          } else {
            return bot.sendMessage(
              chatId,
              "Invalid password. Please try again."
            );
          }
        } catch (error) {
          console.error("Error fetching account details:", error.message);
        }
      });
    });

  // Clear the step since we got the expected input
  delete userSteps[chatId];
});

bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;

  // Send a message with inline buttons
  bot.sendMessage(
    chatId,
    "👋 Welcome to Suitcase, a Web3 Wallet Manager \n \n\n Your gateway to securely manage your Web3 wallet right from Telegram \n \n🚀 Features:\n > 🗝 Manage Your Wallet: Check your balances, view transaction history, and manage tokens.\n\n >💸 Send & Receive Crypto: Easily transfer tokens to other addresses or receive them with your wallet QR code.\n\n >🛡 Stay Secure: Keep track of your private keys and always stay in control of your assets. \n\n To login to your wallet - /login",
    {
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Create a new Wallet", callback_data: "new" },
            { text: "Import an exisiting Wallet", callback_data: "import" },
          ],
        ],
      },
    }
  );
});

// Select the network - ALl import code under this
bot.on("callback_query", (callbackQuery) => {
  const message = callbackQuery.message;
  const data = callbackQuery.data;
  const chatId = message.chat.id;

  if (data === "new") {
    bot
      .sendMessage(
        chatId,
        "Let's create your new wallet!\n\n Firstly select your network:-\n\n  ",
        {
          reply_markup: {
            inline_keyboard: [
              [
                { text: "Solana", callback_data: "sol" },
                { text: "Etherium", callback_data: "eth" },
              ],
            ],
            wallet,
          },
        }
      )
      .then(() => {
        // Store that we expect the wallet name next
        userSteps[chatId] = "expecting_network";
      });
  } else if (data === "import") {
    // Ask the user to provide their private key to import the wallet
    bot
      .sendMessage(chatId, "Please provide the private key for your :", {
        reply_markup: {
          force_reply: true,
        },
      })
      .then(() => {
        bot.on("message", async (msg) => {
          const chatId = msg.chat.id;
          const privateKey = msg.text; // Get user input
          const userId = msg.from.id; // Retrieve the user ID

          bot
            .sendMessage(
              chatId,
              "Please enter the password for your account:-\n\n",
              {
                reply_markup: {
                  force_reply: true,
                },
              }
            )
            .then(() => {
              bot.on("message", async (msg) => {
                const chatId = msg.chat.id;
                const password = msg.text; // Get user input
                const userId = msg.from.id; // Retrieve the user ID
                const saltRounds = 10; //etrieve the user ID
                const passwordHash = await bcrypt.hash(password, saltRounds);
                const encryptedPrivateKey = encrypt(wallet.privateKeys);

                // Create a new user and save to MongoDB
                const newUser = new User({
                  userId: userId,
                  passwordHash: passwordHash,
                  walletInfo: {
                    address: wallet.publicKeys,
                    privateKey: encryptedPrivateKey,
                  },
                });

                newUser
                  .save()
                  .then(() =>
                    bot.sendMessage(
                      msg.chat.id,
                      "Registration successful!,Your wallet address is " +
                        wallet.publicKeys +
                        "\n\n To go to your wallet type /login"
                    )
                  )
                  .catch((err) =>
                    bot.sendMessage(msg.chat.id, `Error: ${err.message}`)
                  );
              });
            });
        });

        // Store that we expect a private key next
        userSteps[chatId] = "expecting_private_key";
      });
  }

  // Acknowledge the callback to avoid Telegram API errors
  bot.answerCallbackQuery(callbackQuery.id);
});

//Based on user inputs we will store the steps
// Listen for messages to capture user input
bot.on("callback_query", (callbackQuery) => {
  const data = callbackQuery.data;
  const message = callbackQuery.message;
  const chatId = message.chat.id;

  if (data === "sol") {
    // Create wallet logic here...
    bot.sendMessage(chatId, `Your new Solana wallet is on the way 🎉`, {
      reply_markup: {
        inline_keyboard: [
          [{ text: "Create seed phrase", callback_data: "sol_seed" }],
        ],
      },
    });
  } else if (data === "eth") {
    // Create wallet logic here...
    bot.sendMessage(chatId, `Your new Etherium wallet is on the way 🎉`, {
      reply_markup: {
        inline_keyboard: [
          [{ text: "Create seed phrase", callback_data: "eth_seed" }],
        ],
      },
    });
  }
});

// Listen for button clicks
//Here i have given the seed phrase to the user and then i will create its account.
bot.on("callback_query", (callbackQuery) => {
  const message = callbackQuery.message;
  const data = callbackQuery.data;
  const chatId = message.chat.id;
  const userId = message.from.id;

  if (data === "sol_seed") {
    // Generate a seed phrase
    const seed = generateMnemonic();
    userData[userId] = { seed: seed };
    console.log("Before the seed phrase -" + seed);
    bot.sendMessage(
      chatId,
      "Copy the seed phrase below and keep it safe. You will need it to recover your wallet in case you lose access to it.\n\n " +
        seed,
      {
        reply_markup: {
          inline_keyboard: [[{ text: "Next", callback_data: "next" }]],
        },
      }
    );
  } else if (data === "eth_seed") {
    // Generate a seed phrase
    const seed = generateMnemonic();
    userData[userId] = { seed: seed };
    console.log("eth seed phrase -" + seed);
    bot.sendMessage(
      chatId,
      "Copy the seed phrase below and keep it safe. You will need it to recover your wallet in case you lose access to it.\n\n " +
        seed,
      {
        reply_markup: {
          inline_keyboard: [[{ text: "Next", callback_data: "next" }]],
        },
      }
    );
  }

  // Acknowledge the callback to avoid Telegram API errors
  bot.answerCallbackQuery(callbackQuery.id);
});

// Listen for button clicks
//From here the Signup will start....
bot.on("callback_query", (callbackQuery) => {
  const message = callbackQuery.message;
  const data = callbackQuery.data;
  const chatId = message.chat.id;
  const userId = message.from.id;
  console.log("just before creating wallet -" + userData[userId].seed);

  if (data === "next") {
    const wallet = SolanaWallet({
      mnemonic: userData[userId].seed,
    });
    bot
      .sendMessage(
        chatId,
        "Now please create the password for your account:-\n\n",
        {
          reply_markup: {
            force_reply: true,
          },
        }
      )
      .then(() => {
        //Now user have entered the password I will create a new id over db and send the wallet data to it .
        bot.on("message", async (msg) => {
          const chatId = msg.chat.id;
          // Handle wallet creation based on the provided name
          const password = msg.text; // Get user input
          const userId = msg.from.id; //
          const saltRounds = 10; //etrieve the user ID
          const passwordHash = await bcrypt.hash(password, saltRounds);
          const encryptedPrivateKey = encrypt(wallet.privateKeys);

          // Create a new user and save to MongoDB
          const newUser = new User({
            userId: userId,
            passwordHash: passwordHash,
            walletInfo: {
              address: wallet.publicKeys,
              privateKey: encryptedPrivateKey,
            },
          });

          newUser
            .save()
            .then(() =>
              bot.sendMessage(
                msg.chat.id,
                "Registration successful!,Your wallet address is " +
                  wallet.publicKeys +
                  "\n\n To go to your wallet type /login"
              )
            )
            .catch((err) =>
              bot.sendMessage(msg.chat.id, `Error: ${err.message}`)
            );
        });
      });
  }

  // Acknowledge the callback to avoid Telegram API errors
  bot.answerCallbackQuery(callbackQuery.id);
});
