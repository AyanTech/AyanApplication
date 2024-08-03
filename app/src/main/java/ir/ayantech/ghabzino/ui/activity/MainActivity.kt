package ir.ayantech.ghabzino.ui.activity

import android.view.LayoutInflater
import ir.ayantech.ghabzino.databinding.ActivityMainBinding
import ir.ayantech.whygoogle.activity.SwipableWhyGoogleActivity
import ir.ayantech.whygoogle.widget.SwipeBackContainer

class MainActivity : SwipableWhyGoogleActivity<ActivityMainBinding>() {

    override val fragmentHost: SwipeBackContainer
        get() = binding.fragmentContainerFl

    override val binder: (LayoutInflater) -> ActivityMainBinding
        get() = ActivityMainBinding::inflate

}