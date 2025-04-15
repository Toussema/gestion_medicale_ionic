import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { NotificationsPagePageRoutingModule } from './notifications-page-routing.module';

import { NotificationsPage } from './notifications-page.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    NotificationsPagePageRoutingModule
  ],
  declarations: [NotificationsPage]
})
export class NotificationsPagePageModule {}
