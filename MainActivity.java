// This code defines an Android activity that loads a URL from Firebase Realtime Database and displays it in a WebView. It also includes a swipe-to-refresh feature and handles file uploads from the WebView.
package com.example.pradeep;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import org.json.JSONObject;
import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    private WebView webView;
    private SwipeRefreshLayout swipeRefresh;
    private LinearLayout welcomeScreen, mainContent;
    private TextView statusText;
    private ValueCallback<Uri[]> filePathCallback;

    // YOUR INSTANT FIREBASE LINK
    private static final String FIREBASE_URL = "https://apk-scanner-805d8-default-rtdb.firebaseio.com/.json";

    private final ActivityResultLauncher<Intent> filePickerLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                if (filePathCallback == null) return;
                Uri[] results = null;
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) results = new Uri[]{uri};
                }
                filePathCallback.onReceiveValue(results);
                filePathCallback = null;
            });

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webView);
        swipeRefresh = findViewById(R.id.swipeRefresh);
        welcomeScreen = findViewById(R.id.welcomeScreen);
        mainContent = findViewById(R.id.mainContent);
        statusText = findViewById(R.id.statusText);
        Button btnStart = findViewById(R.id.btnStart);
        Button btnRefresh = findViewById(R.id.btnRefresh);

        swipeRefresh.setOnRefreshListener(this::fetchUrlAndConnect);

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (webView != null && webView.canGoBack()) {
                    webView.goBack();
                } else {
                    setEnabled(false);
                    onBackPressed();
                }
            }
        });

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback,
                                             FileChooserParams fileChooserParams) {
                MainActivity.this.filePathCallback = filePathCallback;
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                filePickerLauncher.launch(intent);
                return true;
            }
        });

        btnStart.setOnClickListener(v -> fetchUrlAndConnect());
        btnRefresh.setOnClickListener(v -> fetchUrlAndConnect());
    }

    private void fetchUrlAndConnect() {
        runOnUiThread(() -> {
            statusText.setText("Fetching server address from Firebase...");
            swipeRefresh.setRefreshing(true);
        });

        OkHttpClient client = new OkHttpClient.Builder().build();
        Request request = new Request.Builder()
                .url(FIREBASE_URL)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                showError("Network Error: Check internet connection.");
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    try {
                        String responseData = response.body().string();
                        JSONObject jsonObject = new JSONObject(responseData);

                        // Extracting 'url' from Firebase JSON
                        final String fetchedUrl = jsonObject.getString("url");

                        runOnUiThread(() -> {
                            swipeRefresh.setRefreshing(false);
                            welcomeScreen.setVisibility(View.GONE);
                            mainContent.setVisibility(View.VISIBLE);

                            webView.clearCache(true);
                            webView.loadUrl(fetchedUrl);
                        });
                    } catch (Exception e) {
                        showError("Firebase Data Error: 'url' key not found.");
                    }
                } else {
                    showError("Firebase error: " + response.code());
                }
            }
        });
    }

    private void showError(final String message) {
        runOnUiThread(() -> {
            swipeRefresh.setRefreshing(false);
            statusText.setText(message);
            statusText.setTextColor(android.graphics.Color.RED);
            Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG).show();
        });
    }
}


// Original code without dynamic URL loading
// package com.example.pradeep;

// import android.app.Activity;
// import android.content.Intent;
// import android.net.Uri;
// import android.os.Bundle;
// import android.webkit.ValueCallback;
// import android.webkit.WebChromeClient;
// import android.webkit.WebSettings;
// import android.webkit.WebView;
// import android.webkit.WebViewClient;

// import androidx.appcompat.app.AppCompatActivity;

// public class MainActivity extends AppCompatActivity {

//     WebView webView;

//     private ValueCallback<Uri[]> filePathCallback;
//     private final static int FILECHOOSER_RESULTCODE = 1;

//     @Override
//     protected void onCreate(Bundle savedInstanceState) {
//         super.onCreate(savedInstanceState);

//         webView = new WebView(this);
//         setContentView(webView);

//         WebSettings webSettings = webView.getSettings();
//         webSettings.setJavaScriptEnabled(true);
//         webSettings.setAllowFileAccess(true);

//         webView.setWebViewClient(new WebViewClient());

//         webView.setWebChromeClient(new WebChromeClient() {

//             @Override
//             public boolean onShowFileChooser(WebView webView,
//                                              ValueCallback<Uri[]> filePathCallback,
//                                              FileChooserParams fileChooserParams) {

//                 MainActivity.this.filePathCallback = filePathCallback;

//                 Intent intent = fileChooserParams.createIntent();

//                 try {
//                     startActivityForResult(intent, FILECHOOSER_RESULTCODE);
//                 } catch (Exception e) {
//                     return false;
//                 }

//                 return true;
//             }
//         });

//         webView.loadUrl("http://10.87.112.149:5000");
//     }

//     @Override
//     protected void onActivityResult(int requestCode, int resultCode, Intent data) {

//         if (requestCode == FILECHOOSER_RESULTCODE) {

//             if (filePathCallback == null) return;

//             Uri[] results = null;

//             if (resultCode == Activity.RESULT_OK) {

//                 if (data != null) {

//                     Uri uri = data.getData();

//                     if (uri != null) {
//                         results = new Uri[]{uri};
//                     }
//                 }
//             }

//             filePathCallback.onReceiveValue(results);
//             filePathCallback = null;
//         }

//         super.onActivityResult(requestCode, resultCode, data);
//     }
// }


// The activity_main.xml file defines the layout of the app. It includes a welcome screen with a title, status text, and a "Get Started" button. Once the user clicks the button, the main content is displayed, which consists of a refresh button and a WebView wrapped in a SwipeRefreshLayout for pull-to-refresh functionality.
// <?xml version="1.0" encoding="utf-8"?>
// <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
//     android:layout_width="match_parent"
//     android:layout_height="match_parent"
//     android:background="#FFFFFF">

//     <LinearLayout
//         android:id="@+id/welcomeScreen"
//         android:layout_width="match_parent"
//         android:layout_height="match_parent"
//         android:gravity="center"
//         android:orientation="vertical"
//         android:padding="30dp"
//         android:visibility="visible">

//         <TextView
//             android:layout_width="wrap_content"
//             android:layout_height="wrap_content"
//             android:text="APK Scanner"
//             android:textColor="#333333"
//             android:textSize="28sp"
//             android:textStyle="bold" />

//         <TextView
//             android:id="@+id/statusText"
//             android:layout_width="wrap_content"
//             android:layout_height="wrap_content"
//             android:layout_marginTop="12dp"
//             android:text="Ready to connect..."
//             android:textAlignment="center"
//             android:textColor="#666666"
//             android:textSize="16sp" />

//         <Button
//             android:id="@+id/btnStart"
//             android:layout_width="200dp"
//             android:layout_height="wrap_content"
//             android:layout_marginTop="40dp"
//             android:backgroundTint="#2196F3"
//             android:text="Get Started"
//             android:textColor="#FFFFFF" />
//     </LinearLayout>

//     <LinearLayout
//         android:id="@+id/mainContent"
//         android:layout_width="match_parent"
//         android:layout_height="match_parent"
//         android:orientation="vertical"
//         android:visibility="gone">

//         <Button
//             android:id="@+id/btnRefresh"
//             android:layout_width="match_parent"
//             android:layout_height="wrap_content"
//             android:backgroundTint="#4CAF50"
//             android:text="Refresh Link"
//             android:textColor="#FFFFFF" />

//         <androidx.swiperefreshlayout.widget.SwipeRefreshLayout
//             android:id="@+id/swipeRefresh"
//             android:layout_width="match_parent"
//             android:layout_height="match_parent">

//             <WebView
//                 android:id="@+id/webView"
//                 android:layout_width="match_parent"
//                 android:layout_height="match_parent" />

//         </androidx.swiperefreshlayout.widget.SwipeRefreshLayout>
//     </LinearLayout>

// </FrameLayout>

// The AndroidManifest.xml file defines the permissions and activities for the app. It allows internet access and specifies that the MainActivity is the entry point of the app. The usesCleartextTraffic attribute is set to true to allow loading non-HTTPS URLs, which is necessary for testing with local servers or certain APIs that do not support HTTPS.

// <?xml version="1.0" encoding="utf-8"?>
// <manifest xmlns:android="http://schemas.android.com/apk/res/android"
//     package="com.example.pradeep">

//     <uses-permission android:name="android.permission.INTERNET" />

//     <application
//         android:allowBackup="true"
//         android:icon="@mipmap/ic_launcher"
//         android:label="@string/app_name"
//         android:roundIcon="@mipmap/ic_launcher_round"
//         android:supportsRtl="true"
//         android:theme="@style/Theme.MaterialComponents.Light.NoActionBar"
//         android:usesCleartextTraffic="true">

//         <activity
//             android:name=".MainActivity"
//             android:exported="true">
//             <intent-filter>
//                 <action android:name="android.intent.action.MAIN" />
//                 <category android:name="android.intent.category.LAUNCHER" />
//             </intent-filter>
//         </activity>
//     </application>

// </manifest>

// This is the build.gradle file for the Android application. It defines the plugins, Android configuration, and dependencies required for the app to function properly. The app uses AndroidX libraries, OkHttp for HTTP requests, and includes testing dependencies for unit and instrumentation tests.
// plugins {
//     alias(libs.plugins.android.application)
// }

// android {
//     namespace = "com.example.pradeep"
//     compileSdk {
//         version = release(36) {
//             minorApiLevel = 1
//         }
//     }

//     defaultConfig {
//         applicationId = "com.example.pradeep"
//         minSdk = 24
//         targetSdk = 36
//         versionCode = 1
//         versionName = "1.0"

//         testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
//     }

//     buildTypes {
//         release {
//             isMinifyEnabled = false
//             proguardFiles(
//                 getDefaultProguardFile("proguard-android-optimize.txt"),
//                 "proguard-rules.pro"
//             )
//         }
//     }
//     compileOptions {
//         sourceCompatibility = JavaVersion.VERSION_11
//         targetCompatibility = JavaVersion.VERSION_11
//     }
// }

// dependencies {
//     // AndroidX libraries
//     implementation("androidx.appcompat:appcompat:1.6.1")
//     implementation("com.google.android.material:material:1.10.0")
//     implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
//     implementation("com.squareup.okhttp3:okhttp:4.11.0")

//     // OkHttp for HTTP requests (dynamic URL fetch)
//     implementation("com.squareup.okhttp3:okhttp:4.11.0")

//     // Unit testing
//     testImplementation("junit:junit:4.13.2")

//     // Android Instrumentation tests
//     androidTestImplementation("androidx.test.ext:junit:1.1.6")
//     androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
// }