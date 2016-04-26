package com.lookout.borderpatrol.test

import com.lookout.borderpatrol._


class BinderSpec extends BorderPatrolSuite {

  override def afterEach(): Unit = {
    try {
      super.afterEach() // To be stackable, must call super.afterEach
    }
    finally {
      Binder.clear
    }
  }
}
