import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { MedecinDetailPageRoutingModule } from './medecin-detail-routing.module';

import { MedecinDetailPage } from './medecin-detail.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    MedecinDetailPageRoutingModule
  ],
  declarations: [MedecinDetailPage]
})
export class MedecinDetailPageModule {}
