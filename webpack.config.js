/*
 * This config builds a minified version that can be imported
 * anywhere without any dependencies.
 */
const path = require("path");
const webpack = require("webpack");
const SDK_VERSION = require("./package.json").version;

const serverConfig = {
    entry: {
        core: "./src/index.js"
    },
    output: {
        path: path.join(__dirname, "dist"),
        filename: "node/@ping-identity/p14c-js-sdk-auth.js",
        libraryTarget: "umd",
        globalObject: "this"
    },
    target: "node",
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                enforce: "pre",
                use: {
                    loader: "babel-loader",
                    options: {
                        presets: ["@babel/env"],
                        plugins: ["@babel/plugin-transform-runtime"],
                        sourceType: "unambiguous"
                    }
                }
            }
        ]
    },
    plugins: [
        new webpack.DefinePlugin({
            SDK_VERSION: JSON.stringify(SDK_VERSION)
        })
    ],
    // Excluding dependencies from the output bundles.
    // Instead, the created bundle relies on that dependency to be present in the consumer's environment
    externals: ["tls", "net", "fs"],
    devtool: "source-map"
};

const clientConfig = {
    entry: {
        core: "./src/index.js"
    },
    output: {
        path: path.join(__dirname, "dist"),
        filename: "browser/@ping-identity/p14c-js-sdk-auth.js",
        libraryTarget: "umd",
        globalObject: "this"
    },
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                enforce: "pre",
                use: {
                    loader: "babel-loader",
                    options: {
                        presets: ["@babel/env"],
                        plugins: ["@babel/plugin-transform-runtime"],
                        sourceType: "unambiguous"
                    }
                }
            }
        ]
    },
    plugins: [
        new webpack.DefinePlugin({
            SDK_VERSION: JSON.stringify(SDK_VERSION)
        })
    ],
    devtool: "source-map"
};

module.exports = [ serverConfig, clientConfig ];
