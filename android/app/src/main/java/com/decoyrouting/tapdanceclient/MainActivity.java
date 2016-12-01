package com.decoyrouting.tapdanceclient;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;

import go.proxybind.Proxybind;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        final TextView stdout_tv = (TextView) findViewById(R.id.et_stdout);
        stdout_tv.setMovementMethod(ScrollingMovementMethod.getInstance());

        final TextView tvState = (TextView) findViewById(R.id.state);
        final Button launchButton = (Button) findViewById(R.id.launchButton);

        new Thread() {
            @Override
            public void run() {
                try {
                    while (!isInterrupted()) {
                        Thread.sleep(100);
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                String stats = Proxybind.getStats();
                                Boolean isListening = Proxybind.isListening();
                                tvState.setText(stats);
                                if (isListening) {
                                    launchButton.setText("Stop");
                                } else {
                                    launchButton.setText("Launch");
                                }
                                stdout_tv.append(Proxybind.getLog().toString());
                            }
                        });
                    }
                } catch (InterruptedException e) {
                }
            }
        }.start();

        launchButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    public void run() {
                            try {
                                if (Proxybind.isListening()) {
                                    Proxybind.stop();
                                } else {
                                    Proxybind.listen();
                                }
                            } catch (final Exception ex) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            stdout_tv.append(ex.toString() + "\n");
                                        } catch (Exception e) {
                                        }
                                    }
                                });
                            }
                        }
                }).start();
            }
        });

        try {
            Proxybind.newDecoyProxy(10500);
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
