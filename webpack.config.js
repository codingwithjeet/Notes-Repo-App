const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  entry: {
    main: './frontend/src/js/main.js',
    styles: './frontend/src/styles.css'
  },
  output: {
    path: path.resolve(__dirname, 'frontend/dist'),
    filename: 'js/[name].[contenthash].js',
    clean: true,
    publicPath: '/'
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [
          MiniCssExtractPlugin.loader,
          {
            loader: 'css-loader',
            options: {
              sourceMap: process.env.NODE_ENV !== 'production'
            }
          }
        ]
      },
      {
        test: /\.(png|svg|jpg|jpeg|gif)$/i,
        type: 'asset',
        parser: {
          dataUrlCondition: {
            maxSize: 8 * 1024 // 8kb - inline smaller images
          }
        },
        generator: {
          filename: 'images/[name].[hash][ext]'
        }
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          format: {
            comments: false,
          },
          compress: {
            drop_console: process.env.NODE_ENV === 'production',
            drop_debugger: true
          }
        },
        extractComments: false
      })
    ],
    splitChunks: {
      chunks: 'all',
      minSize: 20000,
      minChunks: 1,
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all'
        }
      }
    }
  },
  performance: {
    maxAssetSize: 300000, // 500kb
    maxEntrypointSize: 300000,
    hints: process.env.NODE_ENV === 'production' ? 'warning' : false
  },
  plugins: [
    new MiniCssExtractPlugin({
      filename: 'css/[name].[contenthash].css'
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/index.html',
      filename: 'index.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production' ? {
        removeComments: true,
        collapseWhitespace: true,
        removeRedundantAttributes: true,
        useShortDoctype: true,
        removeEmptyAttributes: true,
        removeStyleLinkTypeAttributes: true,
        keepClosingSlash: true,
        minifyJS: true,
        minifyCSS: true,
        minifyURLs: true,
      } : false
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/login.html',
      filename: 'login.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production'
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/signup.html',
      filename: 'signup.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production'
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/student-dashboard.html',
      filename: 'student-dashboard.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production'
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/teacher-dashboard.html',
      filename: 'teacher-dashboard.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production'
    }),
    new HtmlWebpackPlugin({
      template: './frontend/src/upload.html',
      filename: 'upload.html',
      chunks: ['main', 'styles'],
      minify: process.env.NODE_ENV === 'production'
    }),
    new CopyPlugin({
      patterns: [
        {
          from: 'frontend/public',
          to: 'assets',
          globOptions: {
            ignore: ['**/*.js', '**/*.css'] // Don't copy JS and CSS files
          }
        }
      ]
    })
  ],
  devtool: process.env.NODE_ENV === 'production' ? false : 'source-map'
}; 